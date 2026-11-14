"""Measure NetTrack against a small, known external TCP transfer.

Uses Cloudflare's public speed-test endpoints:
  GET  https://speed.cloudflare.com/__down?bytes=N
  POST https://speed.cloudflare.com/__up

Run from the repository root:
    python tools/diagnose_external_tcp_traffic.py

The test transfers 128 KiB down and 128 KiB up (plus protocol overhead).
It keeps one HTTPS/TCP connection open so AppMonitor has time to discover it
and enable per-connection statistics before transferring the test payload.
"""

import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from services.app_monitor import AppMonitor


HOST = "speed.cloudflare.com"
TRANSFER_BYTES = 128 * 1024
POLL_INTERVAL_SECONDS = 2
CHILD_HOLD_SECONDS = 5

CHILD_CODE = r"""
import http.client
import json
import ssl
import sys
import time
from urllib.parse import urlencode

host = sys.argv[1]
size = int(sys.argv[2])
hold_seconds = float(sys.argv[3])

connection = http.client.HTTPSConnection(
    host,
    timeout=30,
    context=ssl.create_default_context(),
)

try:
    # Establish TCP + TLS first. The parent monitor gets several polling
    # opportunities to discover this connection before the payload transfer.
    connection.connect()
    time.sleep(6)

    connection.request("GET", "/__down?" + urlencode({"bytes": size}))
    download_response = connection.getresponse()
    downloaded = download_response.read()
    download_status = download_response.status
    if download_status != 200:
        raise RuntimeError(
            f"Download endpoint returned HTTP {download_status}"
        )

    upload_payload = b"N" * size
    connection.request(
        "POST",
        "/__up",
        body=upload_payload,
        headers={
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(upload_payload)),
        },
    )
    upload_response = connection.getresponse()
    upload_response.read()
    upload_status = upload_response.status
    if upload_status < 200 or upload_status >= 300:
        raise RuntimeError(f"Upload endpoint returned HTTP {upload_status}")

    print(json.dumps({
        "download_status": download_status,
        "upload_status": upload_status,
        "downloaded_bytes": len(downloaded),
        "uploaded_bytes": len(upload_payload),
    }))

    # Leave the same TCP connection established while the parent takes
    # additional samples after the transfer.
    time.sleep(hold_seconds)
finally:
    connection.close()
"""


def main():
    print("=" * 68)
    print("NETTRACK - EXTERNAL TCP TRAFFIC DIAGNOSTIC")
    print("=" * 68)
    print(f"Remote host: {HOST}")
    print(f"Expected payload: {TRANSFER_BYTES:,} bytes down and up")
    print(f"Sampling interval: {POLL_INTERVAL_SECONDS} seconds")
    print("Estimated payload usage: about 256 KiB, plus network overhead.")
    print("This test uses one persistent HTTPS connection.")

    monitor = AppMonitor()
    monitor.get_usage()  # Clear/establish the monitor's initial baseline.

    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            CHILD_CODE,
            HOST,
            str(TRANSFER_BYTES),
            str(CHILD_HOLD_SECONDS),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    observed_sent = 0
    observed_received = 0

    try:
        while process.poll() is None:
            time.sleep(POLL_INTERVAL_SECONDS)
            for row in monitor.get_usage():
                if row["pid"] == process.pid:
                    observed_sent += row["bytes_sent"]
                    observed_received += row["bytes_received"]

        stdout, stderr = process.communicate(timeout=10)

        # Take one final sample while the child may still have a live socket.
        for row in monitor.get_usage():
            if row["pid"] == process.pid:
                observed_sent += row["bytes_sent"]
                observed_received += row["bytes_received"]

        if process.returncode != 0:
            raise RuntimeError(
                "External traffic generator failed. "
                f"Details: {stderr.strip() or stdout.strip()}"
            )

        import json

        result = json.loads(stdout.strip().splitlines()[-1])
        print("\nREMOTE TRANSFER")
        print("----------------")
        print(f"Download HTTP status: {result['download_status']}")
        print(f"Upload HTTP status:   {result['upload_status']}")
        print(f"Payload downloaded:   {result['downloaded_bytes']:,} bytes")
        print(f"Payload uploaded:     {result['uploaded_bytes']:,} bytes")

        print("\nNETTRACK OBSERVATION")
        print("--------------------")
        print(f"Target process PID:   {process.pid}")
        print(f"Observed upload:      {observed_sent:,} bytes")
        print(f"Observed download:    {observed_received:,} bytes")
        print("\nNote: TCP counters include protocol overhead, so observed totals")
        print("may be higher than the application payload sizes.")
        if observed_sent or observed_received:
            print("RESULT: NetTrack observed traffic on the external TCP connection.")
        else:
            print("RESULT: NetTrack observed zero traffic; investigate EStats")
            print("activation/readout on an external connection before changing")
            print("the short-lived-connection handling.")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


if __name__ == "__main__":
    main()
