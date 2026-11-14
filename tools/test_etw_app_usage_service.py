"""Tests for ETW application usage persistence service."""
import unittest

from services.etw_app_usage_service import ETWAppUsageService


class FakeMonitor:
    def __init__(self):
        self.started = False
        self.stopped = False
        self.rows = [{
            "pid": 42,
            "application": "browser.exe",
            "process_created": 123.0,
            "bytes_sent": 30,
            "bytes_received": 70,
            "total_bytes": 100,
        }]

    def start(self):
        self.started = True

    def collect_once(self):
        return list(self.rows)

    def stop(self):
        self.stopped = True


class FakeDatabase:
    def __init__(self):
        self.saved = []
        self.totals_requested = False

    def save_app_usage(self, applications):
        self.saved.append(list(applications))

    def get_app_totals(self):
        self.totals_requested = True
        return []


class ETWAppUsageServiceTests(unittest.TestCase):
    def test_collect_once_persists_etw_usage(self):
        monitor = FakeMonitor()
        database = FakeDatabase()
        service = ETWAppUsageService(
            interval=1,
            monitor=monitor,
            database=database,
        )

        result = service.collect_once()
        self.assertEqual(result[0]["total_bytes"], 100)
        self.assertEqual(len(database.saved), 1)
        self.assertEqual(database.saved[0][0]["bytes_received"], 70)

    def test_empty_sample_is_not_written(self):
        monitor = FakeMonitor()
        monitor.rows = []
        database = FakeDatabase()
        service = ETWAppUsageService(
            monitor=monitor,
            database=database,
        )

        self.assertEqual(service.collect_once(), [])
        self.assertEqual(database.saved, [])

    def test_interval_must_be_positive(self):
        with self.assertRaises(ValueError):
            ETWAppUsageService(interval=0, monitor=FakeMonitor(),
                               database=FakeDatabase())


if __name__ == "__main__":
    unittest.main(verbosity=2)
