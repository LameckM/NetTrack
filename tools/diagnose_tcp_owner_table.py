"""Inspect Windows TCP owner-PID tables while a child makes HTTPS traffic.

Run:
    python tools/diagnose_tcp_owner_table.py

This diagnostic prints all ESTABLISHED TCP connections for the child PID
and a compact list of all established connections during the HTTPS transfer.
It does not enable or modify EStats.
"""

import json
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from services.tcp_stats import TCPStatsMonitor

HOST = "speed.cloudflare.com"
SIZE = 32 * 1024

CHILD_CODE = r"""
import http.client
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
    print("CONNECTED", flush=True)
    time.sleep(10)
    conn.request("GET", "/__down?" + urlencode({"bytes": size}))
    response = conn.getresponse()
    payload = response.read()
    print("RESULT", response.status, len(payload), flush=True)
    time.sleep(10)
finally:
    conn.close()
"""


def main():
    monitor = TCPStatsMonitor()
    child = subprocess.Popen(
        [sys.executable, "-c", CHILD_CODE, HOST, str(SIZE)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    print("=" * 68)
    print("NETTRACK - WINDOWS TCP OWNER-PID DIAGNOSTIC")
    print("=" * 68)
    print(f"Child PID: {child.pid}")
    print("The child holds an HTTPS connection open for inspection.")

    snapshots = 0
    child_rows_seen = 0
    try:
        while child.poll() is None:
            snapshots += 1
            try:
                ipv4 = monitor.get_connections()
                ipv6 = monitor.get_ipv6_connections()
            except Exception as exc:
                print(f"TCP TABLE ERROR: {type(exc).__name__}: {exc}")
                time.sleep(1)
                continue

            all_rows = ipv4 + ipv6
            matches = [row for row in all_rows if row["pid"] == child.pid]

            if matches:
                child_rows_seen += len(matches)
                print(f"\nSNAPSHOT {snapshots}: CHILD CONNECTIONS")
                for row in matches:
                    print(json.dumps(row, sort_keys=True))
            elif snapshots % 2 == 0:
                print(
                    f"Snapshot {snapshots}: no ESTABLISHED row for child PID; "
                    f"IPv4 rows={len(ipv4)}, IPv6 rows={len(ipv6)}"
                )

            if snapshots == 1:
                print("\nSAMPLE OF OTHER ESTABLISHED CONNECTIONS:")
                for row in all_rows[:12]:
                    print(json.dumps(row, sort_keys=True))

            time.sleep(1)

        stdout, stderr = child.communicate(timeout=10)
        print("\nCHILD OUTPUT:")
        print(stdout.strip() or "(no stdout)")
        if stderr.strip():
            print("\nCHILD STDERR:")
            print(stderr.strip())

        print("\nSUMMARY:")
        print(f"Snapshots taken: {snapshots}")
        print(f"Child connection rows observed: {child_rows_seen}")
        print("If rows for the child appear here, compare their PID/family")
        print("with the earlier EStats diagnostic. If none appear, investigate")
        print("the TCP table enumeration/structure parsing next.")
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()


if __name__ == "__main__":
    main()
