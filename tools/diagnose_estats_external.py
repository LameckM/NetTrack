"""Trace each Windows EStats call for a controlled external HTTPS transfer.

Run from the repository root:
    python tools/diagnose_estats_external.py

Transfers 64 KiB up and down through Cloudflare speed-test endpoints.
This script bypasses AppMonitor's exception handling so Windows API errors
are visible. It does not change production monitoring code.
"""

import json
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlencode

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from services.tcp_stats import TCPStatsMonitor

HOST = "speed.cloudflare.com"
PAYLOAD_SIZE = 64 * 1024
POLL_SECONDS = 1

CHILD_CODE = r"""
import http.client
import json
import ssl
import sys
import time
from urllib.parse import urlencode

host = sys.argv[1]
size = int(sys.argv[2])
conn = http.client.HTTPSConnection(
    host, timeout=30, context=ssl.create_default_context()
)
try:
    conn.connect()
    time.sleep(7)
    conn.request("GET", "/__down?" + urlencode({"bytes": size}))
    response = conn.getresponse()
    downloaded = response.read()
    download_status = response.status

    conn.request(
        "POST", "/__up", body=b"X" * size,
        headers={"Content-Type": "application/octet-stream",
                 "Content-Length": str(size)}
    )
    upload_response = conn.getresponse()
    upload_response.read()
    upload_status = upload_response.status

    print(json.dumps({
        "download_status": download_status,
        "upload_status": upload_status,
        "downloaded": len(downloaded),
        "uploaded": size,
    }), flush=True)
    time.sleep(7)
finally:
    conn.close()
"""


def connection_key(connection):
    return (
        connection.get("family", "IPv4"),
        connection["pid"],
        connection["local_ip"],
        connection.get("local_scope_id", 0),
        connection["local_port"],
        connection["remote_ip"],
        connection.get("remote_scope_id", 0),
        connection["remote_port"],
    )


def main():
    print("=" * 68)
    print("NETTRACK - EXTERNAL ESTATS API DIAGNOSTIC")
    print("=" * 68)
    print(f"Remote host: {HOST}")
    print(f"Payload: {PAYLOAD_SIZE:,} bytes each direction")
    print("Sampling every second; no production code is modified.")

    monitor = TCPStatsMonitor()
    child = subprocess.Popen(
        [sys.executable, "-c", CHILD_CODE, HOST, str(PAYLOAD_SIZE)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    tracked = {}
    totals = {"sent": 0, "received": 0}
    seen = set()
    errors = []

    try:
        while child.poll() is None:
            try:
                connections = monitor.get_connections()
                connections.extend(monitor.get_ipv6_connections())
            except Exception as exc:
                print(f"TCP TABLE ERROR: {type(exc).__name__}: {exc}")
                errors.append(f"TCP table: {exc}")
                time.sleep(POLL_SECONDS)
                continue

            for connection in connections:
                if connection["pid"] != child.pid:
                    continue

                key = connection_key(connection)
                seen.add(key)

                if key not in tracked:
                    print("\nCONNECTION FOUND:")
                    print(connection)
                    try:
                        if connection.get("family") == "IPv6":
                            monitor.enable_ipv6_collection(connection)
                        else:
                            monitor.enable_collection(connection)
                        print("ENABLE ESTATS: SUCCESS")
                    except Exception as exc:
                        message = f"{type(exc).__name__}: {exc}"
                        print(f"ENABLE ESTATS: FAILED - {message}")
                        errors.append(message)
                        continue

                    try:
                        if connection.get("family") == "IPv6":
                            baseline = monitor.read_ipv6_counters(connection)
                        else:
                            baseline = monitor.read_counters(connection)
                        tracked[key] = baseline
                        print(
                            "INITIAL RAW COUNTERS:",
                            f"sent={baseline['bytes_sent']:,},",
                            f"received={baseline['bytes_received']:,}",
                        )
                    except Exception as exc:
                        message = f"{type(exc).__name__}: {exc}"
                        print(f"INITIAL READ: FAILED - {message}")
                        errors.append(message)
                    continue

                try:
                    if connection.get("family") == "IPv6":
                        current = monitor.read_ipv6_counters(connection)
                    else:
                        current = monitor.read_counters(connection)

                    previous = tracked[key]
                    sent_delta = current["bytes_sent"] - previous["bytes_sent"]
                    received_delta = (
                        current["bytes_received"] - previous["bytes_received"]
                    )
                    print(
                        "RAW SAMPLE:",
                        f"sent={current['bytes_sent']:,},",
                        f"received={current['bytes_received']:,},",
                        f"delta_sent={sent_delta:,},",
                        f"delta_received={received_delta:,}",
                    )
                    if sent_delta >= 0:
                        totals["sent"] += sent_delta
                    if received_delta >= 0:
                        totals["received"] += received_delta
                    tracked[key] = current
                except Exception as exc:
                    message = f"{type(exc).__name__}: {exc}"
                    print(f"READ ESTATS: FAILED - {message}")
                    errors.append(message)

            time.sleep(POLL_SECONDS)

        stdout, stderr = child.communicate(timeout=10)
        if child.returncode != 0:
            print("\nTRAFFIC GENERATOR FAILED:")
            print(stderr.strip() or stdout.strip())
        else:
            result = json.loads(stdout.strip().splitlines()[-1])
            print("\nREMOTE TRANSFER:")
            print(f"Download HTTP status: {result['download_status']}")
            print(f"Upload HTTP status:   {result['upload_status']}")
            print(f"Downloaded: {result['downloaded']:,} bytes")
            print(f"Uploaded:   {result['uploaded']:,} bytes")

        print("\nESTATS SUMMARY:")
        print(f"Target PID: {child.pid}")
        print(f"Connections found: {len(seen)}")
        print(f"Connections with baselines: {len(tracked)}")
        print(f"Observed sent delta: {totals['sent']:,} bytes")
        print(f"Observed received delta: {totals['received']:,} bytes")
        print(f"API errors: {len(errors)}")
        if errors:
            for error in errors:
                print(f" - {error}")
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()


if __name__ == "__main__":
    main()
