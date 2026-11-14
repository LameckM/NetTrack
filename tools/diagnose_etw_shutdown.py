"""Measure pywintrace event parsing and shutdown behavior.

Run from an elevated PowerShell:
    python tools/diagnose_etw_shutdown.py

This diagnostic does not write application usage to the database.
"""
import os
import sys
import threading
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.etw_app_monitor import ETWAppMonitor


def main():
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
        print(f"Consumer thread: {consumer.process_thread.name}")
        print("Generate normal Chrome traffic during the 20-second capture.")
        try:
            time.sleep(20)
        except KeyboardInterrupt:
            print("Capture interrupted; proceeding to shutdown.")

        with metrics_lock:
            captured = dict(metrics)
            captured["by_event_id"] = dict(metrics["by_event_id"])

        average_ms = (
            captured["total_seconds"] / captured["events"] * 1000
            if captured["events"] else 0
        )
        print("\nEVENT PARSING METRICS")
        print(f"Events parsed:             {captured['events']}")
        print(f"Events currently parsing:  {captured['active']}")
        print(f"Total parse/callback time: {captured['total_seconds']:.3f}s")
        print(f"Average per event:         {average_ms:.3f}ms")
        print(f"Maximum per event:         {captured['max_seconds'] * 1000:.3f}ms")
        print(f"Event IDs:                 {captured['by_event_id']}")

        print("\nSTOP STAGE 1: stopping ETW provider...", flush=True)
        started = time.monotonic()
        session.provider.stop()
        print(
            f"Provider stop returned in {time.monotonic() - started:.3f}s.",
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
            started_close = time.monotonic()
            result = close_trace(handle)
            print(
                f"CloseTrace returned {result} in "
                f"{time.monotonic() - started_close:.3f}s",
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
        shutdown.start()
        shutdown.join(30)

        print(f"Consumer stop helper alive: {shutdown.is_alive()}")
        print(f"ETW ProcessTrace thread alive: {consumer.process_thread.is_alive()}")
        print(f"Consumer end_capture set: {consumer.end_capture.is_set()}")
        print(f"Consumer stop error: {result['error']}")

        frames = sys._current_frames()
        print("\nCONSUMER THREAD STACK:")
        ident = consumer.process_thread.ident
        if ident in frames:
            print("".join(traceback.format_stack(frames[ident])))
        else:
            print("No Python frame found; consumer thread has exited.")

        print("\nRESULT: parsing metrics and shutdown state captured.")
    finally:
        etw_impl.EventConsumer._processEvent = original_process_event
        if "etw_impl" in locals():
            # The provider is stopped above. Restore the library function even
            # if the diagnostic is interrupted or reports an error.
            pass


if __name__ == "__main__":
    main()
