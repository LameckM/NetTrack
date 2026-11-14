"""Real-time ETW prototype for short-lived application traffic.

Run in elevated PowerShell:
    python -m pip install https://github.com/fireeye/pywintrace/releases/download/v0.3.0/pywintrace-0.3.0-py3-none-any.whl
    python tools/diagnose_etw_realtime.py

This isolated diagnostic sends about 48 KiB of HTTPS payload to
speed.cloudflare.com. It does not replace AppMonitor or write to the database.
"""
import ctypes
import http.client
import os
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urlencode

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from services.etw_event_accounting import (  # noqa: E402
    RECEIVE_EVENT_IDS, SEND_EVENT_IDS, ETWTrafficCounter,
)

HOST = "speed.cloudflare.com"
PROVIDER_GUID = "{7DD42A49-5329-4832-8DFD-43D979153A88}"
KEYWORDS_IPV4_IPV6 = 0x30
TRACE_LEVEL = 5
CONTROL_BYTES = 16 * 1024
BURST_BYTES = 4 * 1024
BURST_CONNECTIONS = 2
TIMEOUT_SECONDS = 30


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def make_connection():
    return http.client.HTTPSConnection(
        HOST, timeout=TIMEOUT_SECONDS,
        context=ssl.create_default_context(),
    )


def transfer(connection, size):
    connection.request("GET", "/__down?" + urlencode({"bytes": size}))
    response = connection.getresponse()
    downloaded = response.read()
    if response.status != 200 or len(downloaded) != size:
        raise RuntimeError(
            f"Download failed: HTTP {response.status}, "
            f"{len(downloaded)} of {size} bytes"
        )
    payload = b"N" * size
    connection.request(
        "POST", "/__up", body=payload,
        headers={
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(payload)),
        },
    )
    upload_response = connection.getresponse()
    upload_response.read()
    if not 200 <= upload_response.status < 300:
        raise RuntimeError(f"Upload failed: HTTP {upload_response.status}")
    return len(payload), len(downloaded)


def run_test_traffic():
    expected_sent = expected_received = 0
    persistent = make_connection()
    try:
        persistent.connect()
        time.sleep(1.0)
        sent, received = transfer(persistent, CONTROL_BYTES)
        expected_sent += sent
        expected_received += received
    finally:
        persistent.close()

    for _ in range(BURST_CONNECTIONS):
        short_lived = make_connection()
        try:
            short_lived.connect()
            sent, received = transfer(short_lived, BURST_BYTES)
            expected_sent += sent
            expected_received += received
        finally:
            short_lived.close()
    return expected_sent, expected_received


def main():
    print("=" * 68)
    print("NETTRACK - REAL-TIME ETW APPLICATION TRAFFIC PROTOTYPE")
    print("=" * 68)
    if os.name != "nt":
        raise SystemExit("This prototype only runs on Windows.")
    if not is_admin():
        raise SystemExit(
            "Administrator privileges are required. Reopen PowerShell "
            "using 'Run as administrator' and try again."
        )

    try:
        import etw
    except ImportError as exc:
        raise SystemExit(
            "Missing optional dependency. Run: "
            "python -m pip install https://github.com/fireeye/pywintrace/releases/download/v0.3.0/pywintrace-0.3.0-py3-none-any.whl"
        ) from exc

    target_pid = os.getpid()
    counter = ETWTrafficCounter()
    callback_errors = []

    def on_event(event):
        try:
            event_id, payload = event
            counter.record(event_id, payload)
        except Exception as exc:
            callback_errors.append(repr(exc))

    provider = etw.ProviderInfo(
        "Microsoft-Windows-Kernel-Network",
        etw.GUID(PROVIDER_GUID),
        level=TRACE_LEVEL,
        any_keywords=KEYWORDS_IPV4_IPV6,
    )
    session = etw.ETW(
        session_name=f"NetTrackRealtime_{target_pid}",
        providers=[provider],
        event_callback=on_event,
        event_id_filters=sorted(SEND_EVENT_IDS | RECEIVE_EVENT_IDS),
    )

    expected_sent = expected_received = 0
    started = False
    try:
        print(f"Test process PID: {target_pid}")
        print(f"Remote host: {HOST}")
        print("Starting real-time Kernel-Network ETW session...")
        session.start()
        started = True
        time.sleep(1.0)
        print("Sending HTTPS traffic: one persistent and two short-lived connections.")
        expected_sent, expected_received = run_test_traffic()
        time.sleep(2.0)
    finally:
        if started:
            session.stop()

    rows = counter.snapshot()
    own = next((row for row in rows if row["pid"] == target_pid), None)

    print("\nTEST PAYLOAD")
    print("------------")
    print(f"Expected upload payload:   {expected_sent:,} bytes")
    print(f"Expected download payload: {expected_received:,} bytes")
    print("\nREAL-TIME ETW RESULTS")
    print("---------------------")
    if own is None:
        print(f"No traffic events were attributed to test PID {target_pid}.")
    else:
        print(f"Attributed PID:            {own['pid']}")
        print(f"ETW upload event bytes:    {own['bytes_sent']:,}")
        print(f"ETW download event bytes:  {own['bytes_received']:,}")
        print(f"Send events:               {own['send_events']}")
        print(f"Receive events:            {own['receive_events']}")
        print(f"Distinct connections:      {own['connection_count']}")
    print(f"Other process rows seen:   {max(0, len(rows) - (1 if own else 0))}")
    if callback_errors:
        print(f"Callback errors:           {len(callback_errors)}")
        print(f"First callback error:      {callback_errors[0]}")

    if own and own["send_events"] and own["receive_events"] and own["connection_count"] >= 3:
        print("\nPASS: Real-time ETW received both directions and distinguished the test connections.")
    else:
        print("\nWARNING: The real-time event capture did not meet all prototype checks.")
    print(
        "Note: ETW event bytes are not guaranteed to equal HTTP payload bytes. "
        "Do not add them to TCP EStats totals."
    )


if __name__ == "__main__":
    main()
