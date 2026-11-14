"""Test provider-side ETW event-ID filtering for NetTrack.

Run from an elevated PowerShell:
    python tools/diagnose_etw_provider_filter.py --duration 30

This is an isolated diagnostic. It does not change the production monitor
or write usage data to the database.
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


def main():
    args = parse_args()
    if os.name != "nt":
        raise SystemExit("This diagnostic requires Windows.")

    try:
        import ctypes
        import etw
        import etw.etw as etw_impl
    except ImportError as exc:
        raise SystemExit("Install pywintrace 0.3.0 before running.") from exc

    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise SystemExit("Open PowerShell as Administrator and run again.")

    # Ask ETW to filter event IDs at the provider/session boundary, before
    # irrelevant records are delivered to pywintrace's consumer.
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
    provider_parameters = etw_impl.ProviderParameters(0, [descriptor])

    event_counts = Counter()
    callback_errors = []
    lock = threading.Lock()

    def on_event(event):
        try:
            event_id, payload = event
            with lock:
                event_counts[int(event_id)] += 1
        except Exception as exc:
            with lock:
                callback_errors.append(repr(exc))

    provider = etw.ProviderInfo(
        "Microsoft-Windows-Kernel-Network",
        etw.GUID(PROVIDER_GUID),
        level=5,
        any_keywords=0x30,
        params=provider_parameters.get(),
    )
    session = etw.ETW(
        session_name=f"NetTrackProviderFilter_{os.getpid()}",
        providers=[provider],
        event_callback=on_event,
        # Deliberately omit consumer-side event_id_filters. We want to see
        # exactly which event IDs the provider-side filter delivers.
    )

    print("NETTRACK - ETW PROVIDER-SIDE EVENT FILTER DIAGNOSTIC")
    print(f"Process PID: {os.getpid()}")
    print(f"Capture duration: {args.duration:.1f}s")
    print(f"Requested event IDs: {SEND_RECEIVE_EVENT_IDS}")
    print("Generate normal Chrome traffic during capture.")

    session.start()
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        print("Capture interrupted; proceeding to shutdown.")

    with lock:
        before_stop = sum(event_counts.values())
        before_counts = dict(event_counts)

    print("\nPROVIDER-FILTERED EVENTS BEFORE SHUTDOWN")
    print(f"Total callback events: {before_stop}")
    print(f"Event IDs received: {before_counts}")

    shutdown_error = []
    def stop_session():
        try:
            session.stop()
        except Exception as exc:
            shutdown_error.append(repr(exc))

    stopper = threading.Thread(
        target=stop_session,
        name="NetTrackProviderFilterShutdown",
        daemon=True,
    )
    started = time.monotonic()
    stopper.start()
    stopper.join(args.shutdown_timeout)
    elapsed = time.monotonic() - started

    with lock:
        after_counts = dict(event_counts)
        after_total = sum(event_counts.values())

    print("\nSHUTDOWN")
    print(f"Shutdown wait: {elapsed:.3f}s")
    print(f"Shutdown helper alive: {stopper.is_alive()}")
    print(
        "ProcessTrace thread alive: "
        f"{session.consumer.process_thread.is_alive()}"
    )
    print(f"Events processed during shutdown: {after_total - before_stop}")
    print(f"Event IDs received overall: {after_counts}")
    print(f"Shutdown errors: {shutdown_error}")
    print(f"Callback errors: {callback_errors[:3]}")

    unexpected = sorted(set(after_counts) - set(SEND_RECEIVE_EVENT_IDS))
    if unexpected:
        print(
            "\nRESULT: provider-side filtering did not exclude all "
            f"unrequested event IDs: {unexpected}"
        )
    elif stopper.is_alive():
        print(
            "\nRESULT: provider-side filtering worked, but shutdown "
            "exceeded the configured timeout."
        )
    else:
        print(
            "\nRESULT: only requested event IDs reached the callback; "
            "inspect the shutdown time and event volume."
        )


if __name__ == "__main__":
    main()
