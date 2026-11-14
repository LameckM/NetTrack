"""Benchmark selective PID/size extraction from raw Kernel-Network ETW events.

Run from elevated PowerShell:
    python tools/diagnose_etw_selective_decode.py --duration 30

This diagnostic uses raw ETW records and asks TDH for only PID and size. It
does not write to the database or modify the production monitor.
"""
import argparse
import ctypes as ct
import ctypes.wintypes as wt
import os
import threading
import time
from collections import Counter, defaultdict

SEND_EVENT_IDS = {10, 26, 42, 58}
RECEIVE_EVENT_IDS = {11, 27, 43, 59}
FILTER_EVENT_IDS = sorted(SEND_EVENT_IDS | RECEIVE_EVENT_IDS)
PROVIDER_GUID = "{7DD42A49-5329-4832-8DFD-43D979153A88}"
ERROR_SUCCESS = 0
ERROR_INSUFFICIENT_BUFFER = 122
MAX_UINT = 0xFFFFFFFF


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=float, default=30)
    parser.add_argument("--shutdown-timeout", type=float, default=120)
    args = parser.parse_args()
    if args.duration <= 0 or args.shutdown_timeout <= 0:
        parser.error("duration and shutdown-timeout must be greater than zero")
    return args


def make_provider_parameters(etw_impl):
    event_filter = etw_impl.ep.EVENT_FILTER_EVENT_ID(True, FILTER_EVENT_IDS)
    filter_size = (
        ct.sizeof(etw_impl.ep.EVENT_FILTER_EVENT_ID)
        + len(FILTER_EVENT_IDS) * ct.sizeof(ct.c_ushort)
    )
    descriptor = etw_impl.ep.EVENT_FILTER_DESCRIPTOR(
        ct.addressof(event_filter._buf),
        filter_size,
        etw_impl.ep.EVENT_FILTER_TYPE_EVENT_ID,
    )
    parameters = etw_impl.ProviderParameters(0, [descriptor])
    descriptor_buffer = (ct.c_char * ct.sizeof(
        etw_impl.ep.EVENT_FILTER_DESCRIPTOR
    ))()
    ct.memmove(
        ct.addressof(descriptor_buffer),
        ct.byref(descriptor),
        ct.sizeof(etw_impl.ep.EVENT_FILTER_DESCRIPTOR),
    )
    parameters._descriptor_buffer = descriptor_buffer
    parameters._event_filter = event_filter
    parameters._props.contents.EnableFilterDesc = ct.cast(
        ct.pointer(descriptor_buffer),
        ct.POINTER(etw_impl.ep.EVENT_FILTER_DESCRIPTOR),
    )
    parameters._props.contents.FilterDescCount = 1
    return parameters


class SelectiveEventDecoder:
    """Cache event metadata and extract only the PID and size properties."""

    def __init__(self, etw_impl, tdh):
        self.etw_impl = etw_impl
        self.tdh = tdh
        self.schemas = {}

    def _schema_for(self, record, event_id):
        version = int(record.contents.EventHeader.EventDescriptor.Version)
        key = (event_id, version)
        cached = self.schemas.get(key)
        if cached is not None:
            return cached

        info = self.etw_impl.EventConsumer._getEventInformation(record)
        base = ct.cast(info, ct.c_void_p).value
        properties = ct.cast(
            info.contents.EventPropertyInfoArray,
            ct.POINTER(self.tdh.EVENT_PROPERTY_INFO),
        )
        offsets = {}
        for index in range(info.contents.TopLevelPropertyCount):
            prop = properties[index]
            name = ct.wstring_at(base + prop.NameOffset)
            if name.lower() in {"pid", "size"}:
                offsets[name.lower()] = int(prop.NameOffset)

        if "pid" not in offsets or "size" not in offsets:
            raise ValueError(
                f"Event {event_id} v{version} lacks PID/size properties: "
                f"{sorted(offsets)}"
            )

        pid_descriptor = self.tdh.PROPERTY_DATA_DESCRIPTOR(
            base + offsets["pid"], MAX_UINT, 0
        )
        size_descriptor = self.tdh.PROPERTY_DATA_DESCRIPTOR(
            base + offsets["size"], MAX_UINT, 0
        )
        # Retain info so the PropertyName pointers remain valid.
        cached = (info, pid_descriptor, size_descriptor)
        self.schemas[key] = cached
        return cached

    def _read_integer(self, record, descriptor):
        size = wt.ULONG()
        status = self.tdh.TdhGetPropertySize(
            record, 0, None, 1, ct.byref(descriptor), ct.byref(size)
        )
        if status != ERROR_SUCCESS:
            raise OSError(status, "TdhGetPropertySize failed")
        if size.value not in (1, 2, 4, 8):
            raise ValueError(f"Unexpected integer property size: {size.value}")

        buffer = (ct.c_byte * size.value)()
        status = self.tdh.TdhGetProperty(
            record, 0, None, 1, ct.byref(descriptor),
            size.value, ct.cast(buffer, ct.POINTER(ct.c_byte))
        )
        if status != ERROR_SUCCESS:
            raise OSError(status, "TdhGetProperty failed")
        return int.from_bytes(bytes(buffer), "little", signed=False)

    def decode(self, record, event_id):
        _info, pid_descriptor, size_descriptor = self._schema_for(
            record, event_id
        )
        pid = self._read_integer(record, pid_descriptor)
        size = self._read_integer(record, size_descriptor)
        return pid, size


def main():
    args = parse_args()
    if os.name != "nt":
        raise SystemExit("This diagnostic requires Windows.")

    try:
        import ctypes
        import etw
        import etw.etw as etw_impl
        from etw import tdh
        from etw.common import RETURN_RAW_UNFORMATTED_DATA
    except ImportError as exc:
        raise SystemExit("Install pywintrace 0.3.0 before running.") from exc

    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise SystemExit("Open PowerShell as Administrator and run again.")

    parameters = make_provider_parameters(etw_impl)
    decoder = SelectiveEventDecoder(etw_impl, tdh)
    event_counts = Counter()
    totals = defaultdict(lambda: {"sent": 0, "received": 0, "events": 0})
    callback_errors = []
    lock = threading.Lock()

    def on_raw_event(event):
        try:
            _unused_event_id, record = event
            event_id = int(
                record.contents.EventHeader.EventDescriptor.Id
            )
            if event_id not in FILTER_EVENT_IDS:
                return
            pid, size = decoder.decode(record, event_id)
            if pid <= 0:
                return
            direction = "sent" if event_id in SEND_EVENT_IDS else "received"
            with lock:
                event_counts[event_id] += 1
                totals[pid][direction] += size
                totals[pid]["events"] += 1
        except Exception as exc:
            with lock:
                if len(callback_errors) < 10:
                    callback_errors.append(repr(exc))

    provider = etw.ProviderInfo(
        "Microsoft-Windows-Kernel-Network",
        etw.GUID(PROVIDER_GUID),
        level=5,
        any_keywords=0x30,
        params=parameters.get(),
    )
    session = etw.ETW(
        session_name=f"NetTrackSelective_{os.getpid()}",
        providers=[provider],
        event_callback=on_raw_event,
        callback_data_flag=RETURN_RAW_UNFORMATTED_DATA,
    )

    print("NETTRACK - RAW ETW SELECTIVE PROPERTY DECODING")
    print(f"Process PID: {os.getpid()}")
    print(f"Capture duration: {args.duration:.1f}s")
    print(f"Shutdown timeout: {args.shutdown_timeout:.1f}s")
    print(f"Provider event-ID filter: {FILTER_EVENT_IDS}")
    print("Extracting only payload PID and size; generate Chrome traffic.")

    session.start()
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        print("Capture interrupted; proceeding to shutdown.")

    with lock:
        before_counts = dict(event_counts)
        before_total = sum(event_counts.values())
        before_totals = {
            pid: dict(values) for pid, values in totals.items()
        }

    print("\nSELECTIVELY DECODED EVENTS BEFORE SHUTDOWN")
    print(f"Decoded events: {before_total}")
    print(f"Event IDs: {before_counts}")
    print(f"Processes attributed: {len(before_totals)}")
    own = before_totals.get(os.getpid(), {})
    print(
        "This diagnostic process: "
        f"uploaded={own.get('sent', 0)} bytes, "
        f"downloaded={own.get('received', 0)} bytes, "
        f"events={own.get('events', 0)}"
    )
    print(f"Cached event schemas: {len(decoder.schemas)}")

    shutdown_errors = []

    def stop_session():
        try:
            session.stop()
        except Exception as exc:
            shutdown_errors.append(repr(exc))

    stopper = threading.Thread(
        target=stop_session,
        name="NetTrackSelectiveDecodeShutdown",
        daemon=True,
    )
    started = time.monotonic()
    stopper.start()
    stopper.join(args.shutdown_timeout)
    elapsed = time.monotonic() - started

    with lock:
        after_counts = dict(event_counts)
        after_total = sum(event_counts.values())
        after_totals = {
            pid: dict(values) for pid, values in totals.items()
        }

    print("\nSELECTIVE DECODER SHUTDOWN")
    print(f"Shutdown wait: {elapsed:.3f}s")
    print(f"Shutdown helper alive: {stopper.is_alive()}")
    print(
        "ProcessTrace thread alive: "
        f"{session.consumer.process_thread.is_alive()}"
    )
    print(f"Events decoded during shutdown: {after_total - before_total}")
    print(f"Event IDs overall: {after_counts}")
    print(f"Processes attributed overall: {len(after_totals)}")
    own = after_totals.get(os.getpid(), {})
    print(
        "This diagnostic process overall: "
        f"uploaded={own.get('sent', 0)} bytes, "
        f"downloaded={own.get('received', 0)} bytes, "
        f"events={own.get('events', 0)}"
    )
    print(f"Cached event schemas: {len(decoder.schemas)}")
    print(f"Shutdown errors: {shutdown_errors}")
    print(f"Callback errors: {callback_errors[:5]}")

    if callback_errors:
        print("\nRESULT: selective property decoding encountered errors.")
    elif stopper.is_alive():
        print("\nRESULT: selective decoder exceeded the shutdown timeout.")
    else:
        print(
            "\nRESULT: selective PID/size decoding completed; compare "
            "throughput and shutdown time with both previous diagnostics."
        )


if __name__ == "__main__":
    main()
