import unittest

from services.etw_event_accounting import ETWTrafficCounter


class ETWTrafficCounterTests(unittest.TestCase):
    def setUp(self):
        self.counter = ETWTrafficCounter()

    def event(self, pid=1500, size=100, sport=50000):
        return {
            "PID": pid,
            "size": size,
            "saddr": "192.168.43.193",
            "daddr": "162.159.140.220",
            "sport": sport,
            "dport": 443,
        }

    def test_send_and_receive_events_are_aggregated(self):
        self.assertTrue(self.counter.record(10, self.event(size=120)))
        self.assertTrue(self.counter.record(11, self.event(size=240)))
        self.assertEqual(self.counter.snapshot(), [{
            "pid": 1500, "bytes_sent": 120, "bytes_received": 240,
            "total_bytes": 360, "send_events": 1, "receive_events": 1,
            "connection_count": 1,
        }])

    def test_distinct_connections_are_counted_separately(self):
        self.counter.record(10, self.event(sport=50000))
        self.counter.record(10, self.event(sport=50001))
        self.assertEqual(self.counter.snapshot()[0]["connection_count"], 2)

    def test_multiple_processes_are_kept_separate(self):
        self.counter.record(10, self.event(pid=1500, size=100))
        self.counter.record(11, self.event(pid=2000, size=250))
        rows = {row["pid"]: row for row in self.counter.snapshot()}
        self.assertEqual(rows[1500]["bytes_sent"], 100)
        self.assertEqual(rows[1500]["bytes_received"], 0)
        self.assertEqual(rows[2000]["bytes_sent"], 0)
        self.assertEqual(rows[2000]["bytes_received"], 250)

    def test_event_header_pid_is_not_used_for_attribution(self):
        payload = self.event(pid=" 1500 ", size=" 517 ")
        payload["EventHeader"] = {"ProcessId": 3276}
        self.counter.record(10, payload)
        self.assertEqual(self.counter.snapshot()[0]["pid"], 1500)

    def test_unknown_or_malformed_events_are_ignored(self):
        self.assertFalse(self.counter.record(99, self.event()))
        self.assertFalse(self.counter.record(10, {"PID": "bad", "size": 10}))
        self.assertFalse(self.counter.record(11, {"PID": 0, "size": 10}))
        self.assertFalse(self.counter.record(11, {"PID": 1500, "size": -1}))
        self.assertEqual(self.counter.snapshot(), [])

    def test_snapshot_is_detached(self):
        self.counter.record(10, self.event())
        snapshot = self.counter.snapshot()
        snapshot[0]["bytes_sent"] = 999
        self.assertEqual(self.counter.snapshot()[0]["bytes_sent"], 100)


if __name__ == "__main__":
    unittest.main()
