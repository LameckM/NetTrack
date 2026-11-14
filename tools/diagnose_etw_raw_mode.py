"""Benchmark pywintrace raw ETW records against its TDH-decoded path.

Run from elevated PowerShell:
    python tools/diagnose_etw_raw_mode.py --duration 30

This is a diagnostic only. It does not write usage data or alter production
monitoring. Raw mode deliberately counts event IDs only; it does not attempt
to account bytes or attribute traffic to applications.
"""
import argparse
import ctypes as ct
import os
import threading
import time
from collections import Counter

SEND_RECEIVE_EVENT_IDS = [10, 11, 26, 27, 42, 43, 58, 59]
PROVIDER_GUID = "{7DD42A49-5329-4832-8DFD-43D979153A88}"


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=float, default=30)
    parser.add_argument("--shutdown-timeout", type=float, default=120)
    args = parser.parse_args()
    if args.duration <= 0 or args.shutdown_timeout <= 0:
        parser.error("duration and shutdown-timeout must be greater than zero")
    return args


def make_provider_parameters(etw_impl):
    event_filter = etw_impl.ep.EVENT_FILTER_EVENT_ID(
        True, SEND_RECEIVE_EVENT_IDS
    )
    filter_size = (
        ct.sizeof(etw_impl.ep.EVENT_FILTER_EVENT_ID)
        + len(SEND_RECEIVE_EVENT_IDS) * ct.sizeof(ct.c_ushort)
    )
    descriptor = etw_impl.ep.EVENT_FILTER_DESCRIPTOR(
        ct.addressof(event_filter._buf),
        filter_size,
        etw_impl.ep.EVENT_FILTER_TYPE_EVENT_ID,
    )
    parameters = etw_impl.ProviderParameters(0, [descriptor])

    # Retain the descriptor storage for the lifetime of the ETW session.
    descriptor_buffer = (ct.c_char * ct.sizeof(
        etw_impl.ep.EVENT_FILTER_DESCRIPTOR
    ))()
    ct.memmove(
        ct.addressof(descriptor_buffer),
        ct.byref(descriptor),
        ct.sizeof(etw_impl.ep.EVENT_FILTER_DESCRIPTOR),
    )
    parameters._descriptor_buffer = descriptor_buffer
    parameters._props.contents.EnableFilterDesc = ct.cast(
        ct.pointer(descriptor_buffer),
        ct.POINTER(etw_impl.ep.EVENT_FILTER_DESCRIPTOR),
    )
    parameters._props.contents.FilterDescCount = 1
    # Keep the source filter object alive too.
    parameters._event_filter = event_filter
    return parameters


def main():
    args = parse_args()
    if os.name != "nt":
        raise SystemExit("This diagnostic requires Windows.")

    try:
        import ctypes
        import etw
        import etw.etw as etw_impl
        from etw.common import RETURN_RAW_UNFORMATTED_DATA
    except ImportError as exc:
        raise SystemExit("Install pywintrace 0.3.0 before running.") from exc

    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise SystemExit("Open PowerShell as Administrator and run again.")

    parameters = make_provider_parameters(etw_impl)
    event_counts = Counter()
    callback_errors = []
    lock = threading.Lock()

    def on_raw_event(event):
        try:
            _callback_event_id, record = event
            event_id = int(
                record.contents.EventHeader.EventDescriptor.Id
            )
            with lock:
                event_counts[event_id] += 1
        except Exception as exc:
            with lock:
                callback_errors.append(repr(exc))

    provider = etw.ProviderInfo(
        "Microsoft-Windows-Kernel-Network",
        etw.GUID(PROVIDER_GUID),
        level=5,
        any_keywords=0x30,
        params=parameters.get(),
    )
    session = etw.ETW(
        session_name=f"NetTrackRawDiag_{os.getpid()}",
        providers=[provider],
        event_callback=on_raw_event,
        callback_data_flag=RETURN_RAW_UNFORMATTED_DATA,
    )

    print("NETTRACK - ETW RAW EVENT MODE DIAGNOSTIC")
    print(f"Process PID: {os.getpid()}")
    print(f"Capture duration: {args.duration:.1f}s")
    print(f"Shutdown timeout: {args.shutdown_timeout:.1f}s")
    print(f"Provider event-ID filter: {SEND_RECEIVE_EVENT_IDS}")
    print("Raw mode skips TDH property decoding; generate Chrome traffic.")

    session.start()
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        print("Capture interrupted; proceeding to shutdown.")

    with lock:
        before_counts = dict(event_counts)
        before_total = sum(event_counts.values())

    print("\nRAW EVENTS BEFORE SHUTDOWN")
    print(f"Total raw callback events: {before_total}")
    print(f"Event IDs received: {before_counts}")

    shutdown_errors = []

    def stop_session():
        try:
            session.stop()
        except Exception as exc:
            shutdown_errors.append(repr(exc))

    stopper = threading.Thread(
        target=stop_session,
        name="NetTrackRawModeShutdown",
        daemon=True,
    )
    started = time.monotonic()
    stopper.start()
    stopper.join(args.shutdown_timeout)
    elapsed = time.monotonic() - started

    with lock:
        after_counts = dict(event_counts)
        after_total = sum(event_counts.values())

    print("\nRAW MODE SHUTDOWN")
    print(f"Shutdown wait: {elapsed:.3f}s")
    print(f"Shutdown helper alive: {stopper.is_alive()}")
    print(
        "ProcessTrace thread alive: "
        f"{session.consumer.process_thread.is_alive()}"
    )
    print(f"Events processed during shutdown: {after_total - before_total}")
    print(f"Event IDs received overall: {after_counts}")
    print(f"Shutdown errors: {shutdown_errors}")
    print(f"Callback errors: {callback_errors[:3]}")

    unexpected = sorted(set(after_counts) - set(SEND_RECEIVE_EVENT_IDS))
    if callback_errors:
        print("\nRESULT: raw callback encountered errors; inspect them above.")
    elif unexpected:
        print(
            "\nRESULT: provider filter delivered unexpected event IDs: "
            f"{unexpected}"
        )
    elif stopper.is_alive():
        print(
            "\nRESULT: raw mode still exceeded the shutdown timeout."
        )
    else:
        print(
            "\nRESULT: raw callback completed; compare shutdown time and "
            "backlog with the TDH-decoded diagnostic."
        )


if __name__ == "__main__":
    main()
