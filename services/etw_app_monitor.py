"""Real-time ETW-backed application traffic monitor for Windows.

ETW is used as the sole source for this monitor. Do not add these event-byte
totals to TCP EStats totals, because that would double-count the same traffic.
"""
import ctypes
import os
import threading

import psutil

from services.etw_event_accounting import (
    RECEIVE_EVENT_IDS,
    SEND_EVENT_IDS,
    ETWTrafficCounter,
)

PROVIDER_GUID = "{7DD42A49-5329-4832-8DFD-43D979153A88}"
KEYWORDS_IPV4_IPV6 = 0x30
TRACE_LEVEL = 5


def is_admin():
    """Return whether the current Windows process is elevated."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


class ETWAppMonitor:
    """Collect per-process network event bytes from a real-time ETW session."""

    def __init__(self, session_name=None, etw_module=None):
        self.session_name = session_name or f"NetTrackAppUsage_{os.getpid()}"
        self._etw_module = etw_module
        self._counter = ETWTrafficCounter()
        self._session = None
        self._started = False
        self._lock = threading.Lock()
        # PID -> (process creation time, last sent bytes, last received bytes)
        self._previous = {}
        self.callback_errors = []

    def _load_etw(self):
        if self._etw_module is not None:
            return self._etw_module
        try:
            import etw
        except ImportError as exc:
            raise RuntimeError(
                "Real-time application monitoring requires pywintrace. "
                "Install it with: python -m pip install "
                "https://github.com/fireeye/pywintrace/releases/download/"
                "v0.3.0/pywintrace-0.3.0-py3-none-any.whl"
            ) from exc
        self._etw_module = etw
        return etw

    def _on_event(self, event):
        """Keep the ETW callback small; resolve process metadata when sampled."""
        try:
            event_id, payload = event
            self._counter.record(event_id, payload)
        except Exception as exc:
            with self._lock:
                self.callback_errors.append(repr(exc))

    def start(self):
        if os.name != "nt":
            raise RuntimeError("ETW application monitoring is available only on Windows.")
        if not is_admin():
            raise PermissionError(
                "Administrator privileges are required for ETW application monitoring."
            )
        if self._started:
            return

        etw = self._load_etw()
        provider = etw.ProviderInfo(
            "Microsoft-Windows-Kernel-Network",
            etw.GUID(PROVIDER_GUID),
            level=TRACE_LEVEL,
            any_keywords=KEYWORDS_IPV4_IPV6,
        )
        session = etw.ETW(
            session_name=self.session_name,
            providers=[provider],
            event_callback=self._on_event,
            event_id_filters=sorted(SEND_EVENT_IDS | RECEIVE_EVENT_IDS),
        )
        session.start()
        self._session = session
        self._started = True

    def collect_once(self):
        """Return per-process byte deltas since the previous collection."""
        if not self._started:
            raise RuntimeError("Start ETWAppMonitor before collecting usage.")

        applications = []
        for row in self._counter.snapshot():
            pid = row["pid"]
            try:
                process = psutil.Process(pid)
                application = process.name()
                process_created = process.create_time()
            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
                OSError,
            ):
                continue

            current_sent = row["bytes_sent"]
            current_received = row["bytes_received"]
            previous = self._previous.get(pid)

            if previous is None:
                # First observation includes all events recorded since the
                # ETW session began.
                sent = current_sent
                received = current_received
            elif previous[0] != process_created:
                # PID was reused. Do not attribute the previous process's
                # accumulated ETW events to the new process instance.
                sent = 0
                received = 0
            else:
                sent = max(0, current_sent - previous[1])
                received = max(0, current_received - previous[2])

            self._previous[pid] = (
                process_created,
                current_sent,
                current_received,
            )

            if sent <= 0 and received <= 0:
                continue

            applications.append({
                "pid": pid,
                "application": application,
                "process_created": process_created,
                "bytes_sent": sent,
                "bytes_received": received,
                "total_bytes": sent + received,
            })

        return sorted(
            applications,
            key=lambda item: item["total_bytes"],
            reverse=True,
        )

    def stop(self):
        if not self._started:
            return
        session = self._session
        self._session = None
        self._started = False
        if session is not None:
            session.stop()

