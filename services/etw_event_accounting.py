"""Thread-safe accounting for decoded Kernel-Network ETW events.

This module is independent of the ETW session controller so aggregation can be
tested on non-Windows systems. ETW event bytes are not guaranteed application
payload bytes and must not be added to TCP EStats totals.
"""
from threading import Lock

SEND_EVENT_IDS = frozenset({10, 26, 42, 58})
RECEIVE_EVENT_IDS = frozenset({11, 27, 43, 59})
TRAFFIC_EVENT_IDS = SEND_EVENT_IDS | RECEIVE_EVENT_IDS


def _to_int(value):
    if isinstance(value, bytes):
        value = value.decode("ascii", errors="strict")
    return int(str(value).strip())


class ETWTrafficCounter:
    """Aggregate Kernel-Network event bytes by owning process PID."""

    def __init__(self):
        self._lock = Lock()
        self._by_pid = {}

    def record(self, event_id, event_data):
        """Record an event using its payload PID, not the ETW header PID."""
        if event_id not in TRAFFIC_EVENT_IDS or not isinstance(event_data, dict):
            return False
        try:
            pid = _to_int(event_data.get("PID"))
            size = _to_int(event_data.get("size"))
        except (TypeError, ValueError, UnicodeDecodeError):
            return False
        if pid <= 0 or size < 0:
            return False

        connection = None
        parts = [
            str(event_data.get("saddr", "")).strip(),
            str(event_data.get("sport", "")).strip(),
            str(event_data.get("daddr", "")).strip(),
            str(event_data.get("dport", "")).strip(),
        ]
        if all(parts):
            connection = tuple(parts)

        with self._lock:
            row = self._by_pid.setdefault(pid, {
                "pid": pid,
                "bytes_sent": 0,
                "bytes_received": 0,
                "send_events": 0,
                "receive_events": 0,
                "connections": set(),
            })
            if event_id in SEND_EVENT_IDS:
                row["bytes_sent"] += size
                row["send_events"] += 1
            else:
                row["bytes_received"] += size
                row["receive_events"] += 1
            if connection is not None:
                row["connections"].add(connection)
        return True

    def snapshot(self):
        """Return detached, serializable per-PID totals."""
        with self._lock:
            rows = [{
                "pid": row["pid"],
                "bytes_sent": row["bytes_sent"],
                "bytes_received": row["bytes_received"],
                "total_bytes": row["bytes_sent"] + row["bytes_received"],
                "send_events": row["send_events"],
                "receive_events": row["receive_events"],
                "connection_count": len(row["connections"]),
            } for row in self._by_pid.values()]
        return sorted(rows, key=lambda item: item["total_bytes"], reverse=True)
