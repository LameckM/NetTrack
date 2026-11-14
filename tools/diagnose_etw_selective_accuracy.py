"""Controlled accuracy test for selective raw ETW PID/size decoding.

Run in elevated PowerShell:
    python tools/diagnose_etw_selective_accuracy.py

Sends a known HTTPS payload over one persistent and two short-lived
connections. Reports ETW bytes attributed to this process. ETW event bytes
include transport/protocol overhead and are not expected to equal payload
bytes exactly. No database or production monitor is changed.
"""
import argparse
import ctypes as ct
import ctypes.wintypes as wt
import http.client
import os
import ssl
import threading
import time
from collections import Counter, defaultdict
from urllib.parse import urlencode

SEND_EVENT_IDS = {10, 26, 42, 58}
RECEIVE_EVENT_IDS = {11, 27, 43, 59}
FILTER_EVENT_IDS = sorted(SEND_EVENT_IDS | RECEIVE_EVENT_IDS)
PROVIDER_GUID = "{7DD42A49-5329-4832-8DFD-43D979153A88}"
HOST = "speed.cloudflare.com"
PERSISTENT_BYTES = 16 * 1024
SHORT_BYTES = 4 * 1024
SHORT_CONNECTIONS = 2
ERROR_SUCCESS = 0
MAX_UINT = 0xFFFFFFFF


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shutdown-timeout", type=float, default=120)
    args = parser.parse_args()
    if args.shutdown_timeout <= 0:
        parser.error("shutdown-timeout must be greater than zero")
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
    def __init__(self, etw_impl, tdh):
        self.etw_impl = etw_impl
        self.tdh = tdh
        self.schemas = {}

    def _schema_for(self, record, event_id):
        version = int(record.contents.EventHeader.EventDescriptor.Version)
        key = (event_id, version)
        if key in self.schemas:
            return self.schemas[key]

        info = self.etw_impl.EventConsumer._getEventInformation(record)
        base = ct.cast(info, ct.c_void_p).value
        props = ct.cast(
            info.contents.EventPropertyInfoArray,
            ct.POINTER(self.tdh.EVENT_PROPERTY_INFO),
        )
        offsets = {}
        for index in range(info.contents.TopLevelPropertyCount):
            prop = props[index]
            name = ct.wstring_at(base + prop.NameOffset).lower()
            if name in {"pid", "size"}:
                offsets[name] = int(prop.NameOffset)
        if set(offsets) != {"pid", "size"}:
            raise ValueError(
                f"Event {event_id} v{version} missing PID/size: {offsets}"
            )

        result = (
            info,
            self.tdh.PROPERTY_DATA_DESCRIPTOR(base + offsets["pid"], MAX_UINT, 0),
            self.tdh.PROPERTY_DATA_DESCRIPTOR(base + offsets["size"], MAX_UINT, 0),
        )
        self.schemas[key] = result
        return result

    def _read_uint(self, record, descriptor):
        size = wt.ULONG()
        status = self.tdh.TdhGetPropertySize(
            record, 0, None, 1, ct.byref(descriptor), ct.byref(size)
        )
        if status != ERROR_SUCCESS:
            raise OSError(status, "TdhGetPropertySize failed")
        if size.value not in (1, 2, 4, 8):
            raise ValueError(f"Unexpected property width: {size.value}")
        buffer = (ct.c_byte * size.value)()
        status = self.tdh.TdhGetProperty(
            record, 0, None, 1, ct.byref(descriptor), size.value,
            ct.cast(buffer, ct.POINTER(ct.c_byte))
        )
        if status != ERROR_SUCCESS:
            raise OSError(status, "TdhGetProperty failed")
        return int.from_bytes(bytes(buffer), "little")

    def decode(self, record, event_id):
        _info, pid_desc, size_desc = self._schema_for(record, event_id)
        return (
            self._read_uint(record, pid_desc),
            self._read_uint(record, size_desc),
        )


def transfer(connection, size):
    connection.request("GET", "/__down?" + urlencode({"bytes": size}))
    response = connection.getresponse()
    body = response.read()
    if response.status != 200 or len(body) != size:
        raise RuntimeError(
            f"Download failed: HTTP {response.status}, received {len(body)}"
        )

    payload = b"N" * size
    connection.request(
        "POST", "/__up", body=payload,
        headers={
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(payload)),
        },
    )
    response = connection.getresponse()
    response.read()
    if not 200 <= response.status < 300:
        raise RuntimeError(f"Upload failed: HTTP {response.status}")
    return len(body), len(payload)


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

    pid = os.getpid()
    decoder = SelectiveEventDecoder(etw_impl, tdh)
    totals = defaultdict(lambda: {"sent": 0, "received": 0, "events": 0})
    event_counts = Counter()
    errors = []
    lock = threading.Lock()

    def on_event(event):
        try:
            _event_id, record = event
            event_id = int(record.contents.EventHeader.EventDescriptor.Id)
            if event_id not in FILTER_EVENT_IDS:
                return
            owner_pid, size = decoder.decode(record, event_id)
            if owner_pid <= 0:
                return
            direction = "sent" if event_id in SEND_EVENT_IDS else "received"
            with lock:
                event_counts[event_id] += 1
                totals[owner_pid][direction] += size
                totals[owner_pid]["events"] += 1
        except Exception as exc:
            with lock:
                if len(errors) < 10:
                    errors.append(repr(exc))

    provider = etw.ProviderInfo(
        "Microsoft-Windows-Kernel-Network",
        etw.GUID(PROVIDER_GUID),
        level=5,
        any_keywords=0x30,
        params=make_provider_parameters(etw_impl).get(),
    )
    session = etw.ETW(
        session_name=f"NetTrackAccuracy_{pid}",
        providers=[provider],
        event_callback=on_event,
        callback_data_flag=RETURN_RAW_UNFORMATTED_DATA,
    )

    expected_each_direction = PERSISTENT_BYTES + SHORT_CONNECTIONS * SHORT_BYTES
    print("NETTRACK - SELECTIVE ETW CONTROLLED ACCURACY TEST")
    print(f"Process PID: {pid}")
    print(f"Remote host: {HOST}")
    print(f"Expected payload each direction: {expected_each_direction:,} bytes")
    print("Connections: 1 persistent control + 2 short-lived connections")
    print("Starting real-time ETW capture...")
    session.start()

    successful_connections = 0
    payload_down = 0
    payload_up = 0
    context = ssl.create_default_context()
    try:
        persistent = http.client.HTTPSConnection(
            HOST, timeout=30, context=context
        )
        try:
            persistent.connect()
            # Let ETW observe the established socket before transferring.
            time.sleep(1)
            down, up = transfer(persistent, PERSISTENT_BYTES)
            payload_down += down
            payload_up += up
            successful_connections += 1
        finally:
            persistent.close()

        for _ in range(SHORT_CONNECTIONS):
            short = http.client.HTTPSConnection(
                HOST, timeout=30, context=context
            )
            try:
                down, up = transfer(short, SHORT_BYTES)
                payload_down += down
                payload_up += up
                successful_connections += 1
            finally:
                short.close()
    finally:
        # Allow the final network events to reach the real-time consumer.
        time.sleep(2)

    with lock:
        before = dict(totals.get(pid, {}))
        before_events = sum(event_counts.values())
        before_ids = dict(event_counts)

    print("\nCONTROLLED HTTPS TRANSFER")
    print(f"Connections completed: {successful_connections}")
    print(f"Payload downloaded: {payload_down:,} bytes")
    print(f"Payload uploaded:   {payload_up:,} bytes")

    print("\nETW ATTRIBUTION BEFORE SHUTDOWN")
    print(f"Attributed PID: {pid}")
    print(f"ETW downloaded: {before.get('received', 0):,} bytes")
    print(f"ETW uploaded:   {before.get('sent', 0):,} bytes")
    print(f"Attributed events: {before.get('events', 0):,}")
    print(f"Event IDs: {before_ids}")
    print(f"Cached schemas: {len(decoder.schemas)}")

    stop_errors = []

    def stop():
        try:
            session.stop()
        except Exception as exc:
            stop_errors.append(repr(exc))

    stopper = threading.Thread(target=stop, daemon=True)
    start = time.monotonic()
    stopper.start()
    stopper.join(args.shutdown_timeout)
    shutdown_time = time.monotonic() - start

    with lock:
        after = dict(totals.get(pid, {}))
        after_events = sum(event_counts.values())

    print("\nSHUTDOWN")
    print(f"Shutdown wait: {shutdown_time:.3f}s")
    print(f"Shutdown helper alive: {stopper.is_alive()}")
    print(f"ProcessTrace thread alive: {session.consumer.process_thread.is_alive()}")
    print(f"Events processed during shutdown: {after_events - before_events}")
    print(f"Final ETW downloaded: {after.get('received', 0):,} bytes")
    print(f"Final ETW uploaded:   {after.get('sent', 0):,} bytes")
    print(f"Callback errors: {errors}")
    print(f"Shutdown errors: {stop_errors}")

    if successful_connections != 1 + SHORT_CONNECTIONS:
        print("\nRESULT: one or more controlled connections failed.")
    elif errors or stop_errors or stopper.is_alive():
        print("\nRESULT: inspect callback/shutdown errors above.")
    elif not after.get("received") or not after.get("sent"):
        print("\nRESULT: ETW did not capture both directions for this PID.")
    else:
        print(
            "\nRESULT: ETW attributed bidirectional traffic to the controlled "
            "process across persistent and short-lived connections."
        )
        print("ETW event bytes may exceed payload bytes due to protocol overhead.")


if __name__ == "__main__":
    main()
