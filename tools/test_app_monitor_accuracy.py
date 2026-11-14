"""Accuracy and lifecycle tests for AppMonitor using deterministic TCP counters.

These tests do not require live network traffic or Windows TCP APIs. The separate
IPv6 counter tests cover the real Windows API integration.
"""
import unittest
from unittest.mock import patch

from services.app_monitor import AppMonitor


def make_connection(port, family="IPv4", pid=4321):
    connection = {
        "pid": pid,
        "local_ip": "::1" if family == "IPv6" else "192.0.2.10",
        "local_port": port,
        "remote_ip": "::1" if family == "IPv6" else "198.51.100.20",
        "remote_port": 443,
        "state": 5,
    }
    if family == "IPv6":
        connection.update({
            "local_scope_id": 0,
            "remote_scope_id": 0,
            "family": "IPv6",
        })
    return connection


class FakeProcess:
    created_at = 1000.0

    def __init__(self, pid):
        self.pid = pid

    def name(self):
        return "test-browser.exe"

    def create_time(self):
        return self.created_at


class FakeTCPStatsMonitor:
    connections = []
    counters = {}

    def __init__(self):
        pass

    def get_connections(self):
        return [c for c in self.connections if c.get("family") != "IPv6"]

    def get_ipv6_connections(self):
        return [c for c in self.connections if c.get("family") == "IPv6"]

    @staticmethod
    def _port(connection):
        return connection["local_port"]

    def enable_collection(self, connection):
        self.counters.setdefault(self._port(connection), {
            "bytes_sent": 0,
            "bytes_received": 0,
        })

    def enable_ipv6_collection(self, connection):
        self.enable_collection(connection)

    def read_counters(self, connection):
        return dict(self.counters[self._port(connection)])

    def read_ipv6_counters(self, connection):
        return self.read_counters(connection)


class AppMonitorAccuracyTests(unittest.TestCase):
    def setUp(self):
        FakeProcess.created_at = 1000.0
        FakeTCPStatsMonitor.connections = []
        FakeTCPStatsMonitor.counters = {}
        self.process_patch = patch(
            "services.app_monitor.psutil.Process",
            side_effect=FakeProcess,
        )
        self.stats_patch = patch(
            "services.app_monitor.TCPStatsMonitor",
            FakeTCPStatsMonitor,
        )
        self.process_patch.start()
        self.stats_patch.start()
        self.addCleanup(self.process_patch.stop)
        self.addCleanup(self.stats_patch.stop)

    def test_multiple_connections_are_aggregated_once_per_process(self):
        ipv4 = make_connection(50001)
        ipv6 = make_connection(50002, "IPv6")
        FakeTCPStatsMonitor.connections = [ipv4, ipv6]
        monitor = AppMonitor()

        # Establish baselines for both connections.
        self.assertEqual(monitor.get_usage(), [])

        FakeTCPStatsMonitor.counters[50001] = {
            "bytes_sent": 120,
            "bytes_received": 50,
        }
        FakeTCPStatsMonitor.counters[50002] = {
            "bytes_sent": 80,
            "bytes_received": 70,
        }

        usage = monitor.get_usage()
        self.assertEqual(len(usage), 1)
        self.assertEqual(usage[0]["bytes_sent"], 200)
        self.assertEqual(usage[0]["bytes_received"], 120)
        self.assertEqual(usage[0]["total_bytes"], 320)

    def test_closed_connections_are_removed_from_tracking(self):
        first = make_connection(50011)
        second = make_connection(50012)
        FakeTCPStatsMonitor.connections = [first, second]
        monitor = AppMonitor()
        monitor.get_usage()
        self.assertEqual(len(monitor.previous), 2)

        FakeTCPStatsMonitor.connections = [second]
        monitor.get_usage()

        self.assertEqual(len(monitor.previous), 1)
        remaining_key = next(iter(monitor.previous))
        self.assertEqual(remaining_key[5], 50012)

    def test_process_restart_creates_a_new_tracking_identity(self):
        connection = make_connection(50021)
        FakeTCPStatsMonitor.connections = [connection]
        monitor = AppMonitor()
        monitor.get_usage()

        FakeTCPStatsMonitor.counters[50021] = {
            "bytes_sent": 300,
            "bytes_received": 200,
        }
        FakeProcess.created_at = 2000.0

        # A restarted process with the same PID/endpoint must get a fresh baseline.
        self.assertEqual(monitor.get_usage(), [])
        self.assertEqual(len(monitor.previous), 1)
        self.assertEqual(next(iter(monitor.previous))[2], 2000.0)

        FakeTCPStatsMonitor.counters[50021] = {
            "bytes_sent": 350,
            "bytes_received": 230,
        }
        usage = monitor.get_usage()
        self.assertEqual(usage[0]["bytes_sent"], 50)
        self.assertEqual(usage[0]["bytes_received"], 30)

    def test_counter_reset_never_produces_negative_usage(self):
        connection = make_connection(50031)
        FakeTCPStatsMonitor.connections = [connection]
        monitor = AppMonitor()
        monitor.get_usage()

        FakeTCPStatsMonitor.counters[50031] = {
            "bytes_sent": 500,
            "bytes_received": 400,
        }
        self.assertEqual(monitor.get_usage()[0]["total_bytes"], 900)

        # Simulate a counter reset or a replaced TCP statistics record.
        FakeTCPStatsMonitor.counters[50031] = {
            "bytes_sent": 20,
            "bytes_received": 10,
        }
        reset_usage = monitor.get_usage()
        self.assertEqual(reset_usage[0]["total_bytes"], 0)
        self.assertGreaterEqual(reset_usage[0]["bytes_sent"], 0)
        self.assertGreaterEqual(reset_usage[0]["bytes_received"], 0)

        FakeTCPStatsMonitor.counters[50031] = {
            "bytes_sent": 55,
            "bytes_received": 35,
        }
        next_usage = monitor.get_usage()
        self.assertEqual(next_usage[0]["bytes_sent"], 35)
        self.assertEqual(next_usage[0]["bytes_received"], 25)


if __name__ == "__main__":
    unittest.main(verbosity=2)
