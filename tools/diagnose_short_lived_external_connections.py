"""Compare persistent and short-lived external HTTPS traffic with AppMonitor.

Run from the repository root on Windows:
    python tools/diagnose_short_lived_external_connections.py

This diagnostic uses a small amount of external data (approximately 48 KiB of
application payload) and does not modify production monitoring code.
"""

import http.client
import os
import ssl
import threading
import time
from pathlib import Path
import sys
from urllib.parse import urlencode

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from services.app_monitor import AppMonitor

HOST = "speed.cloudflare.com"
CONTROL_BYTES = 16 * 1024
BURST_BYTES_PER_CONNECTION = 4 * 1024
BURST_CONNECTIONS = 2
POLL_INTERVAL_SECONDS = 2.0
TIMEOUT_SECONDS = 30


def transfer_on_connection(connection, size):
    connection.request("GET", "/__down?" + urlencode({"bytes": size}))
    download_response = connection.getresponse()
    downloaded = download_response.read()
    if download_response.status != 200 or len(downloaded) != size:
        raise RuntimeError(
            f"Download failed: HTTP {download_response.status}, "
            f"{len(downloaded)} of {size} bytes"
        )

    payload = b"N" * size
    connection.request(
        "POST",
        "/__up",
        body=payload,
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


def make_connection():
    return http.client.HTTPSConnection(
        HOST, timeout=TIMEOUT_SECONDS,
        context=ssl.create_default_context()
    )


def usage_for_pid(monitor, pid):
    sent = 0
    received = 0
    for row in monitor.get_usage():
        if row["pid"] == pid:
            sent += row["bytes_sent"]
            received += row["bytes_received"]
    return sent, received


def main():
    print("=" * 68)
    print("NETTRACK - SHORT-LIVED EXTERNAL TCP CONNECTION DIAGNOSTIC")
    print("=" * 68)
    print(f"Remote host: {HOST}")
    print(f"Monitoring PID: {os.getpid()} (this process owns the test sockets)")
    print(f"Configured application polling interval: {POLL_INTERVAL_SECONDS:.0f} seconds")
    print(
        f"Payload: {CONTROL_BYTES:,} bytes each direction on the persistent "
        f"control, then {BURST_CONNECTIONS} short-lived connections with "
        f"{BURST_BYTES_PER_CONNECTION:,} bytes each direction"
    )
    print("Total application payload is approximately 48 KiB.")

    monitor = AppMonitor()
    control_connected = threading.Event()
    allow_control_transfer = threading.Event()
    control_finished = threading.Event()
    burst_ready = threading.Event()
    start_burst = threading.Event()
    burst_finished = threading.Event()
    worker_result = {}
    worker_error = []

    def traffic_worker():
        try:
            # Persistent control: keep one established socket open so the
            # parent can see it and enable EStats before sending payload.
            connection = make_connection()
            try:
                connection.connect()
                control_connected.set()
                if not allow_control_transfer.wait(TIMEOUT_SECONDS):
                    raise TimeoutError("Timed out waiting to start control transfer")
                worker_result["control_sent"], worker_result["control_received"] = (
                    transfer_on_connection(connection, CONTROL_BYTES)
                )
                time.sleep(1.0)
            finally:
                connection.close()
            control_finished.set()

            # Short-lived burst: each connection is opened, used, and closed.
            # The parent deliberately takes its next sample only after this
            # burst, modelling a burst that happens entirely between polls.
            burst_ready.set()
            if not start_burst.wait(TIMEOUT_SECONDS):
                raise TimeoutError("Timed out waiting to start short-lived burst")

            started = time.monotonic()
            total_sent = 0
            total_received = 0
            for _ in range(BURST_CONNECTIONS):
                short_connection = make_connection()
                try:
                    short_connection.connect()
                    sent, received = transfer_on_connection(
                        short_connection, BURST_BYTES_PER_CONNECTION
                    )
                    total_sent += sent
                    total_received += received
                finally:
                    short_connection.close()

            worker_result["burst_sent"] = total_sent
            worker_result["burst_received"] = total_received
            worker_result["burst_duration"] = time.monotonic() - started
        except Exception as exc:
            worker_error.append(exc)
        finally:
            control_finished.set()
            burst_finished.set()

    worker = threading.Thread(target=traffic_worker, daemon=True)
    worker.start()

    observed_control_sent = 0
    observed_control_received = 0
    observed_burst_sent = 0
    observed_burst_received = 0

    try:
        if not control_connected.wait(TIMEOUT_SECONDS):
            raise TimeoutError("Persistent HTTPS connection was not established")

        # First sighting establishes the EStats baseline for the persistent
        # connection. It is intentionally done before payload transfer.
        usage_for_pid(monitor, os.getpid())
        allow_control_transfer.set()

        while not control_finished.wait(0.25):
            sent, received = usage_for_pid(monitor, os.getpid())
            observed_control_sent += sent
            observed_control_received += received

        # Capture any final control-connection deltas before starting burst.
        sent, received = usage_for_pid(monitor, os.getpid())
        observed_control_sent += sent
        observed_control_received += received

        if worker_error:
            raise worker_error[0]

        if not burst_ready.wait(TIMEOUT_SECONDS):
            raise TimeoutError("Short-lived burst did not become ready")

        # Establish the sample immediately before the burst, then do not poll
        # until all short-lived sockets have closed.
        usage_for_pid(monitor, os.getpid())
        sample_started = time.monotonic()
        start_burst.set()

        if not burst_finished.wait(TIMEOUT_SECONDS):
            raise TimeoutError("Short-lived external burst timed out")

        burst_duration = worker_result.get("burst_duration", 0.0)
        elapsed = time.monotonic() - sample_started
        if elapsed < POLL_INTERVAL_SECONDS:
            time.sleep(POLL_INTERVAL_SECONDS - elapsed)

        sent, received = usage_for_pid(monitor, os.getpid())
        observed_burst_sent += sent
        observed_burst_received += received

        if worker_error:
            raise worker_error[0]

        print("\nPERSISTENT CONNECTION CONTROL")
        print("-----------------------------")
        print(f"Expected upload payload:   {worker_result['control_sent']:,} bytes")
        print(f"Observed upload:           {observed_control_sent:,} bytes")
        print(f"Expected download payload: {worker_result['control_received']:,} bytes")
        print(f"Observed download:         {observed_control_received:,} bytes")

        print("\nSHORT-LIVED CONNECTION BURST")
        print("----------------------------")
        print(f"Connections completed:     {BURST_CONNECTIONS}")
        print(f"Expected upload payload:   {worker_result['burst_sent']:,} bytes")
        print(f"Observed upload:           {observed_burst_sent:,} bytes")
        print(f"Expected download payload: {worker_result['burst_received']:,} bytes")
        print(f"Observed download:         {observed_burst_received:,} bytes")
        print(f"Burst duration:            {burst_duration:.2f} seconds")
        print(f"Configured poll interval:  {POLL_INTERVAL_SECONDS:.2f} seconds")

        if burst_duration < POLL_INTERVAL_SECONDS:
            print("\nRESULT: The short-lived burst completed within one polling interval.")
        else:
            print("\nRESULT: The burst took longer than one polling interval.")
            print("Interpret the burst result as a controlled between-samples test,")
            print("not proof that every real-world burst fits inside one poll.")
        print("TCP counters can include protocol overhead; payload totals are references.")
    finally:
        allow_control_transfer.set()
        start_burst.set()
        worker.join(timeout=2)


if __name__ == "__main__":
    main()
