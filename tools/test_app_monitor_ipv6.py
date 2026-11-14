import unittest
from unittest.mock import patch

from services.app_monitor import AppMonitor


class FakeProcess:
    def __init__(self, pid):
        self.pid = pid

    def name(self):
        return "test-browser.exe"

    def create_time(self):
        return 12345.0


class FakeTCPStatsMonitor:
    def __init__(self):
        self.enabled = []
        self.read_counts = {}

    def get_connections(self):
        return [{
            "pid": 4321,
            "local_ip": "192.0.2.10",
            "local_port": 50000,
            "remote_ip": "198.51.100.20",
            "remote_port": 443,
            "state": 5,
        }]

    def get_ipv6_connections(self):
        return [{
            "pid": 4321,
            "local_ip": "2001:db8::10",
            "local_scope_id": 0,
            "local_port": 50001,
            "remote_ip": "2001:db8::20",
            "remote_scope_id": 0,
            "remote_port": 443,
            "state": 5,
            "family": "IPv6",
        }]

    def enable_collection(self, connection):
        self.enabled.append(("IPv4", connection["local_port"]))

    def enable_ipv6_collection(self, connection):
        self.enabled.append(("IPv6", connection["local_port"]))

    def _read(self, family, connection):
        key = (family, connection["local_port"])
        count = self.read_counts.get(key, 0) + 1
        self.read_counts[key] = count
        if count == 1:
            return {"bytes_sent": 100, "bytes_received": 200}
        return {"bytes_sent": 150, "bytes_received": 260}

    def read_counters(self, connection):
        return self._read("IPv4", connection)

    def read_ipv6_counters(self, connection):
        return self._read("IPv6", connection)


class AppMonitorIPv6IntegrationTests(unittest.TestCase):
    @patch("services.app_monitor.psutil.Process", side_effect=FakeProcess)
    @patch("services.app_monitor.TCPStatsMonitor", FakeTCPStatsMonitor)
    def test_ipv4_and_ipv6_usage_are_combined(self, _process):
        monitor = AppMonitor()

        # First poll enables collection and establishes both baselines.
        self.assertEqual(monitor.get_usage(), [])
        self.assertEqual(
            {family for family, _port in monitor.tcp_monitor.enabled},
            {"IPv4", "IPv6"},
        )

        # Second poll reports the counter deltas from both connections.
        usage = monitor.get_usage()
        self.assertEqual(len(usage), 1)
        self.assertEqual(usage[0]["application"], "test-browser.exe")
        self.assertEqual(usage[0]["pid"], 4321)
        self.assertEqual(usage[0]["bytes_sent"], 100)
        self.assertEqual(usage[0]["bytes_received"], 120)
        self.assertEqual(usage[0]["total_bytes"], 220)

    @patch("services.app_monitor.psutil.Process", side_effect=FakeProcess)
    @patch("services.app_monitor.TCPStatsMonitor", FakeTCPStatsMonitor)
    def test_ipv4_and_ipv6_connection_keys_do_not_collide(self, _process):
        monitor = AppMonitor()
        monitor.get_usage()

        self.assertEqual(len(monitor.previous), 2)
        families = {key[0] for key in monitor.previous}
        self.assertEqual(families, {"IPv4", "IPv6"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
