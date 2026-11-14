"""Unit tests for ETW-backed application traffic accounting."""
import unittest
from unittest.mock import patch

from services.etw_app_monitor import ETWAppMonitor


class FakeProcess:
    created_at = 1000.0

    def __init__(self, pid):
        self.pid = pid

    def name(self):
        return "browser.exe"

    def create_time(self):
        return self.created_at


class FakeGuid:
    def __init__(self, value):
        self.value = value


class FakeProviderInfo:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


class FakeSession:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True


class FakeETWModule:
    GUID = FakeGuid
    ProviderInfo = FakeProviderInfo

    def __init__(self):
        self.session = None

    def ETW(self, **kwargs):
        self.session = FakeSession(**kwargs)
        return self.session


class ETWAppMonitorTests(unittest.TestCase):
    def setUp(self):
        FakeProcess.created_at = 1000.0
        self.process_patch = patch(
            "services.etw_app_monitor.psutil.Process",
            side_effect=FakeProcess,
        )
        self.process_patch.start()
        self.addCleanup(self.process_patch.stop)
        self.etw = FakeETWModule()
        self.monitor = ETWAppMonitor(
            session_name="NetTrackUnitTest",
            etw_module=self.etw,
        )

    def start_monitor(self):
        with patch("services.etw_app_monitor.os.name", "nt"), patch(
            "services.etw_app_monitor.is_admin", return_value=True
        ):
            self.monitor.start()

    def test_start_configures_provider_and_stop_closes_session(self):
        self.start_monitor()
        self.assertTrue(self.etw.session.started)
        self.assertEqual(
            self.etw.session.kwargs["session_name"],
            "NetTrackUnitTest",
        )
        self.monitor.stop()
        self.assertTrue(self.etw.session.stopped)

    def test_callback_traffic_is_attributed_and_reported_as_first_sample(self):
        self.start_monitor()
        callback = self.etw.session.kwargs["event_callback"]
        callback((10, {"PID": "4321", "size": "120", "saddr": "a",
                       "sport": "1", "daddr": "b", "dport": "443"}))
        callback((11, {"PID": "4321", "size": "80", "saddr": "b",
                       "sport": "443", "daddr": "a", "dport": "1"}))

        usage = self.monitor.collect_once()
        self.assertEqual(len(usage), 1)
        self.assertEqual(usage[0]["pid"], 4321)
        self.assertEqual(usage[0]["application"], "browser.exe")
        self.assertEqual(usage[0]["bytes_sent"], 120)
        self.assertEqual(usage[0]["bytes_received"], 80)
        self.assertEqual(usage[0]["total_bytes"], 200)

    def test_second_sample_reports_only_new_event_bytes(self):
        self.start_monitor()
        callback = self.etw.session.kwargs["event_callback"]
        callback((10, {"PID": 4321, "size": 100}))
        self.assertEqual(self.monitor.collect_once()[0]["bytes_sent"], 100)

        callback((10, {"PID": 4321, "size": 45}))
        callback((11, {"PID": 4321, "size": 30}))
        usage = self.monitor.collect_once()
        self.assertEqual(usage[0]["bytes_sent"], 45)
        self.assertEqual(usage[0]["bytes_received"], 30)

    def test_pid_reuse_resets_baseline_without_old_process_delta(self):
        self.start_monitor()
        callback = self.etw.session.kwargs["event_callback"]
        callback((10, {"PID": 4321, "size": 100}))
        self.monitor.collect_once()

        FakeProcess.created_at = 2000.0
        callback((10, {"PID": 4321, "size": 50}))
        self.assertEqual(self.monitor.collect_once(), [])

        callback((10, {"PID": 4321, "size": 25}))
        usage = self.monitor.collect_once()
        self.assertEqual(usage[0]["bytes_sent"], 25)
        self.assertEqual(usage[0]["process_created"], 2000.0)

    def test_collection_requires_started_session(self):
        with self.assertRaises(RuntimeError):
            self.monitor.collect_once()

    def test_stop_is_safe_before_start_and_idempotent(self):
        self.monitor.stop()
        self.start_monitor()
        self.monitor.stop()
        self.monitor.stop()
        self.assertTrue(self.etw.session.stopped)


if __name__ == "__main__":
    unittest.main(verbosity=2)
