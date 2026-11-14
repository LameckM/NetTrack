"""Real-time ETW-backed application traffic monitor for Windows.

Raw Kernel-Network events are decoded selectively (PID and size only) to
avoid pywintrace's expensive full payload decoding. ETW is the sole source for
this monitor; do not add these totals to TCP EStats totals.
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
from services.etw_raw_decoder import (
    RawKernelNetworkEventDecoder,
    create_provider_parameters,
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

    def __init__(
        self,
        session_name=None,
        etw_module=None,
        stop_timeout=10.0,
        raw_decoder=None,
        raw_callback_data_flag=None,
        provider_parameters=None,
    ):
        if stop_timeout <= 0:
            raise ValueError("ETW stop timeout must be greater than zero.")
        self.stop_timeout = stop_timeout
        self.session_name = session_name or f"NetTrackAppUsage_{os.getpid()}"
        self._etw_module = etw_module
        self._raw_decoder = raw_decoder
        self._raw_callback_data_flag = raw_callback_data_flag
        self._provider_parameters = provider_parameters
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

    def _load_raw_components(self):
        """Load pywintrace's raw callback mode and selective TDH decoder."""
        if (
            self._raw_decoder is not None
            and self._raw_callback_data_flag is not None
            and self._provider_parameters is not None
        ):
            return

        try:
            import etw.etw as etw_impl
            from etw import tdh
            from etw.common import RETURN_RAW_UNFORMATTED_DATA
        except ImportError as exc:
            raise RuntimeError(
                "The installed pywintrace package does not expose the "
                "required raw ETW callback interfaces."
            ) from exc

        if self._raw_decoder is None:
            self._raw_decoder = RawKernelNetworkEventDecoder(etw_impl, tdh)
        if self._raw_callback_data_flag is None:
            self._raw_callback_data_flag = RETURN_RAW_UNFORMATTED_DATA
        if self._provider_parameters is None:
            self._provider_parameters = create_provider_parameters(etw_impl)

    def _on_event(self, event):
        """Extract PID/size from raw records, then update the thread-safe counter."""
        try:
            _callback_event_id, record = event
            if isinstance(record, dict):
                # Keep direct dictionary callbacks available for unit tests
                # and callers that already supply decoded event payloads.
                event_id = _callback_event_id
                payload = record
            else:
                event_id = int(
                    record.contents.EventHeader.EventDescriptor.Id
                )
                payload = self._raw_decoder.decode(record, event_id)
            if payload is not None:
                self._counter.record(event_id, payload)
        except Exception as exc:
            with self._lock:
                if len(self.callback_errors) < 20:
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
        self._load_raw_components()
        provider = etw.ProviderInfo(
            "Microsoft-Windows-Kernel-Network",
            etw.GUID(PROVIDER_GUID),
            level=TRACE_LEVEL,
            any_keywords=KEYWORDS_IPV4_IPV6,
            params=self._provider_parameters.get(),
        )
        session = etw.ETW(
            session_name=self.session_name,
            providers=[provider],
            event_callback=self._on_event,
            callback_data_flag=self._raw_callback_data_flag,
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
                sent = current_sent
                received = current_received
            elif previous[0] != process_created:
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
            # pywintrace's consumer.stop() performs an unbounded thread.join().
            # Keep the service's main thread responsive if the consumer stalls.
            errors = []

            def stop_session():
                try:
                    session.stop()
                except Exception as exc:
                    errors.append(exc)

            shutdown_thread = threading.Thread(
                target=stop_session,
                name="NetTrackETWShutdown",
                daemon=True,
            )
            shutdown_thread.start()
            shutdown_thread.join(self.stop_timeout)
            if shutdown_thread.is_alive():
                return False
            if errors:
                raise errors[0]
        return True
