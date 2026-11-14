"""Diagnose which pywintrace shutdown stage blocks on Windows.

Run from an elevated PowerShell:
    python tools/diagnose_etw_shutdown.py

This is diagnostic-only; it does not write application usage to the database.
"""
import os
import sys
import threading
import time

import psutil

from services.etw_app_monitor import (
    ETWAppMonitor,
    PROVIDER_GUID,
    KEYWORDS_IPV4_IPV6,
    TRACE_LEVEL,
)


def main():
    if os.name != "nt":
        raise SystemExit("This diagnostic requires Windows.")
    try:
        import etw
        import etw.etw as etw_impl
    except ImportError as exc:
        raise SystemExit("Install pywintrace 0.3.0 before running this diagnostic.") from exc

    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise SystemExit("Open PowerShell as Administrator and run again.")
    except AttributeError:
        raise SystemExit("Unable to verify Administrator privileges.")

    monitor = ETWAppMonitor(session_name=f"NetTrackShutdownDiag_{os.getpid()}")
    monitor.start()
    session = monitor._session
    consumer = session.consumer

    print("NETTRACK - ETW SHUTDOWN DIAGNOSTIC")
    print(f"Process PID: {os.getpid()}")
    print(f"Consumer thread: {consumer.process_thread.name}")
    print("ETW session started. Generate a little Chrome traffic for 10 seconds.")
    try:
        time.sleep(10)
    except KeyboardInterrupt:
        print("Capture interrupted; proceeding to shutdown.")

    original_close_trace = etw_impl.et.CloseTrace

    def tracked_close_trace(handle):
        started = time.monotonic()
        result = original_close_trace(handle)
        print(
            f"CloseTrace(handle={getattr(handle, 'value', handle)}) "
            f"returned {result} in {time.monotonic() - started:.3f}s",
            flush=True,
        )
        return result

    etw_impl.et.CloseTrace = tracked_close_trace
    try:
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
        started = time.monotonic()
        shutdown.start()
        shutdown.join(15)
        print(
            f"Consumer stop wait: {time.monotonic() - started:.3f}s",
            flush=True,
        )
        print(f"Consumer stop thread alive: {shutdown.is_alive()}", flush=True)
        print(
            f"ETW ProcessTrace thread alive: {consumer.process_thread.is_alive()}",
            flush=True,
        )
        print(f"Consumer end_capture set: {consumer.end_capture.is_set()}", flush=True)
        print(f"Consumer stop error: {result['error']}", flush=True)
        print("\nRESULT: inspect the two stop stages above.", flush=True)
    finally:
        etw_impl.et.CloseTrace = original_close_trace


if __name__ == "__main__":
    main()
