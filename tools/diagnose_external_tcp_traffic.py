"""Measure AppMonitor against a known external HTTPS transfer.

Run from the repository root:
    python tools/diagnose_external_tcp_traffic.py

Important: On Windows, sys.executable may be a venv launcher whose PID differs
from the actual Python process. The child therefore reports os.getpid(), and
the monitor filters by that actual socket-owning PID.
"""

import json
import os
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
POLL_INTERVAL_SECONDS = 1
CHILD_HOLD_SECONDS = 8

CHILD_CODE = r"""
import http.client
import json
import os
import ssl
import sys
import time
from urllib.parse import urlencode

host = sys.argv[1]
size = int(sys.argv[2])
hold_seconds = float(sys.argv[3])

connection = http.client.HTTPSConnection(
    host, timeout=30, context=ssl.create_default_context()
)

try:
    connection.connect()
    # Report the PID of the process that actually owns connection.sock.
    print("CHILD_PID", os.getpid(), flush=True)
    print("SOCKET_LOCAL", repr(connection.sock.getsockname()), flush=True)
    print("SOCKET_REMOTE", repr(connection.sock.getpeername()), flush=True)

    # Keep the connection established so the parent can enable EStats first.
    time.sleep(6)

    connection.request("GET", "/__down?" + urlencode({"bytes": size}))
    download_response = connection.getresponse()
    downloaded = download_response.read()
    download_status = download_response.status
    if download_status != 200:
        raise RuntimeError(f"Download endpoint returned HTTP {download_status}")

    upload_payload = b"N" * size
    connection.request(
        "POST", "/__up", body=upload_payload,
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
    }), flush=True)

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
    print(f"Sampling interval: {POLL_INTERVAL_SECONDS} second(s)")
    print("This test uses one persistent HTTPS connection.")

    monitor = AppMonitor()
    monitor.get_usage()

    process = subprocess.Popen(
        [
            sys.executable, "-u", "-c", CHILD_CODE,
            HOST, str(TRANSFER_BYTES), str(CHILD_HOLD_SECONDS),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    observed_sent = 0
    observed_received = 0
    child_pid = None
    child_lines = []

    try:
        # Wait for the actual socket-owning Python process to identify itself.
        deadline = time.time() + 40
        while time.time() < deadline and process.poll() is None:
            line = process.stdout.readline()
            if not line:
                continue
            line = line.strip()
            child_lines.append(line)
            print(f"CHILD: {line}")
            if line.startswith("CHILD_PID "):
                child_pid = int(line.split(maxsplit=1)[1])
                break

        if child_pid is None:
            raise RuntimeError(
                "The traffic process did not report its actual PID. "
                "Child output: " + " | ".join(child_lines)
            )

        print(f"Launcher PID: {process.pid}")
        print(f"Actual socket-owning PID: {child_pid}")

        while process.poll() is None:
            time.sleep(POLL_INTERVAL_SECONDS)
            for row in monitor.get_usage():
                if row["pid"] == child_pid:
                    observed_sent += row["bytes_sent"]
                    observed_received += row["bytes_received"]

        remaining_stdout, stderr = process.communicate(timeout=10)
        child_lines.extend(
            line.strip() for line in remaining_stdout.splitlines() if line.strip()
        )

        # A final sample catches any delta reported before the socket closes.
        for row in monitor.get_usage():
            if row["pid"] == child_pid:
                observed_sent += row["bytes_sent"]
                observed_received += row["bytes_received"]

        if process.returncode != 0:
            raise RuntimeError(
                "External traffic generator failed. "
                f"Details: {stderr.strip() or ' | '.join(child_lines)}"
            )

        result_lines = [
            line for line in child_lines if line.startswith("{")
        ]
        if not result_lines:
            raise RuntimeError("Traffic child did not return transfer results.")
        result = json.loads(result_lines[-1])

        print("\nREMOTE TRANSFER")
        print("----------------")
        print(f"Download HTTP status: {result['download_status']}")
        print(f"Upload HTTP status:   {result['upload_status']}")
        print(f"Payload downloaded:   {result['downloaded_bytes']:,} bytes")
        print(f"Payload uploaded:     {result['uploaded_bytes']:,} bytes")

        print("\nNETTRACK OBSERVATION")
        print("--------------------")
        print(f"Launcher PID:         {process.pid}")
        print(f"Target process PID:   {child_pid}")
        print(f"Observed upload:      {observed_sent:,} bytes")
        print(f"Observed download:    {observed_received:,} bytes")
        print("\nTCP counters may include protocol overhead.")
        if observed_sent or observed_received:
            print("RESULT: NetTrack observed traffic on the external TCP connection.")
        else:
            print("RESULT: NetTrack still observed zero traffic for the actual")
            print("socket-owning PID. Investigate EStats activation/readout next.")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


if __name__ == "__main__":
    main()
