"""Measure pywintrace event parsing and shutdown behavior.

Run from an elevated PowerShell:
    python tools/diagnose_etw_shutdown.py --duration 20
    python tools/diagnose_etw_shutdown.py --duration 90

This diagnostic does not write application usage to the database.
"""
import argparse
import os
import sys
import threading
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.etw_app_monitor import ETWAppMonitor


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--duration",
        type=float,
        default=20,
        help="ETW capture duration in seconds (default: 20).",
    )
    parser.add_argument(
        "--shutdown-timeout",
        type=float,
        default=120,
        help="Maximum consumer shutdown wait in seconds (default: 120).",
    )
    args = parser.parse_args()
    if args.duration <= 0 or args.shutdown_timeout <= 0:
        parser.error("duration and shutdown-timeout must be greater than zero")
    return args


def metric_snapshot(metrics, lock):
    with lock:
        result = dict(metrics)
        result["by_event_id"] = dict(metrics["by_event_id"])
    return result


def print_metrics(title, values):
    average_ms = (
        values["total_seconds"] / values["events"] * 1000
        if values["events"] else 0
    )
    print(f"\n{title}")
    print(f"Events parsed:             {values['events']}")
    print(f"Events currently parsing:  {values['active']}")
    print(f"Total parse/callback time: {values['total_seconds']:.3f}s")
    print(f"Average per event:         {average_ms:.3f}ms")
    print(f"Maximum per event:         {values['max_seconds'] * 1000:.3f}ms")
    print(f"Event IDs:                 {values['by_event_id']}")


def main():
    args = parse_args()
    if os.name != "nt":
        raise SystemExit("This diagnostic requires Windows.")

    try:
        import ctypes
        import etw
        import etw.etw as etw_impl
    except ImportError as exc:
        raise SystemExit(
            "Install pywintrace 0.3.0 before running this diagnostic."
        ) from exc

    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise SystemExit("Open PowerShell as Administrator and run again.")

    metrics = {
        "events": 0,
        "active": 0,
        "total_seconds": 0.0,
        "max_seconds": 0.0,
        "by_event_id": {},
    }
    metrics_lock = threading.Lock()
    original_process_event = etw_impl.EventConsumer._processEvent

    def measured_process_event(consumer_self, record):
        started = time.perf_counter()
        with metrics_lock:
            metrics["active"] += 1
        try:
            return original_process_event(consumer_self, record)
        finally:
            elapsed = time.perf_counter() - started
            try:
                event_id = int(
                    record.contents.EventHeader.EventDescriptor.Id
                )
            except Exception:
                event_id = -1
            with metrics_lock:
                metrics["active"] -= 1
                metrics["events"] += 1
                metrics["total_seconds"] += elapsed
                metrics["max_seconds"] = max(
                    metrics["max_seconds"], elapsed
                )
                metrics["by_event_id"][event_id] = (
                    metrics["by_event_id"].get(event_id, 0) + 1
                )

    etw_impl.EventConsumer._processEvent = measured_process_event
    monitor = ETWAppMonitor(
        session_name=f"NetTrackParseDiag_{os.getpid()}"
    )

    try:
        monitor.start()
        session = monitor._session
        consumer = session.consumer

        print("NETTRACK - ETW PARSING AND SHUTDOWN DIAGNOSTIC")
        print(f"Process PID: {os.getpid()}")
        print(f"Capture duration: {args.duration:.1f}s")
        print(f"Shutdown timeout: {args.shutdown_timeout:.1f}s")
        print(f"Consumer thread: {consumer.process_thread.name}")
        print(
            f"Generate normal Chrome traffic during the "
            f"{args.duration:.0f}-second capture."
        )
        try:
            time.sleep(args.duration)
        except KeyboardInterrupt:
            print("Capture interrupted; proceeding to shutdown.")

        before_stop = metric_snapshot(metrics, metrics_lock)
        print_metrics("EVENT PARSING METRICS BEFORE SHUTDOWN", before_stop)

        print("\nSTOP STAGE 1: stopping ETW provider...", flush=True)
        provider_started = time.monotonic()
        session.provider.stop()
        print(
            f"Provider stop returned in "
            f"{time.monotonic() - provider_started:.3f}s.",
            flush=True,
        )
        print(
            f"Consumer thread alive after provider stop: "
            f"{consumer.process_thread.is_alive()}",
            flush=True,
        )

        print("\nSTOP STAGE 2: stopping ETW consumer...", flush=True)
        close_trace = etw_impl.et.CloseTrace

        def tracked_close_trace(handle):
            close_started = time.monotonic()
            result = close_trace(handle)
            print(
                f"CloseTrace returned {result} in "
                f"{time.monotonic() - close_started:.3f}s",
                flush=True,
            )
            return result

        etw_impl.et.CloseTrace = tracked_close_trace
        result = {"error": None}

        def stop_consumer():
            try:
                consumer.stop()
            except Exception as exc:
                result["error"] = repr(exc)

        shutdown = threading.Thread(
            target=stop_consumer,
            name="NetTrackConsumerStopDiagnostic",
            daemon=True,
        )
        shutdown_started = time.monotonic()
        shutdown.start()
        shutdown.join(args.shutdown_timeout)
        shutdown_elapsed = time.monotonic() - shutdown_started

        after_stop = metric_snapshot(metrics, metrics_lock)
        print(f"Consumer stop wait: {shutdown_elapsed:.3f}s")
        print(f"Consumer stop helper alive: {shutdown.is_alive()}")
        print(
            f"ETW ProcessTrace thread alive: "
            f"{consumer.process_thread.is_alive()}"
        )
        print(f"Consumer end_capture set: {consumer.end_capture.is_set()}")
        print(f"Consumer stop error: {result['error']}")
        print_metrics("EVENT PARSING METRICS AFTER SHUTDOWN WAIT", after_stop)
        print(
            "Events processed during shutdown wait: "
            f"{after_stop['events'] - before_stop['events']}"
        )

        frames = sys._current_frames()
        print("\nCONSUMER THREAD STACK:")
        ident = consumer.process_thread.ident
        if ident in frames:
            print("".join(traceback.format_stack(frames[ident])))
        else:
            print("No Python frame found; consumer thread has exited.")

        if shutdown.is_alive():
            print(
                "\nRESULT: consumer did not finish within the configured "
                "shutdown timeout."
            )
        else:
            print("\nRESULT: consumer shutdown completed.")
    finally:
        etw_impl.EventConsumer._processEvent = original_process_event


if __name__ == "__main__":
    main()
