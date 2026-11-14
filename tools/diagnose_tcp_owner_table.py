"""Compare NetTrack's TCP table parser with Windows netstat for a live child socket.

Run:
    python tools/diagnose_tcp_owner_table.py

The child prints its socket endpoints and holds the HTTPS socket open.
While it is open, this script checks both NetTrack's parsed rows and
Windows netstat -ano output for the child's PID. No EStats calls are made.
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
    print("SOCKET_LOCAL", conn.sock.getsockname(), flush=True)
    print("SOCKET_REMOTE", conn.sock.getpeername(), flush=True)
    time.sleep(12)
    conn.request("GET", "/__down?" + urlencode({"bytes": size}))
    response = conn.getresponse()
    payload = response.read()
    print("RESULT", response.status, len(payload), flush=True)
    time.sleep(12)
finally:
    conn.close()
"""


def netstat_rows(pid):
    result = subprocess.run(
        ["netstat", "-ano", "-p", "tcp"],
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )
    matches = []
    target = str(pid)
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 5 and fields[-1] == target:
            matches.append(line.strip())
    return matches, result.returncode, result.stderr.strip()


def main():
    monitor = TCPStatsMonitor()
    child = subprocess.Popen(
        [sys.executable, "-c", CHILD_CODE, HOST, str(SIZE)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    print("=" * 68)
    print("NETTRACK - WINDOWS TCP OWNER-PID CROSS-CHECK")
    print("=" * 68)
    print(f"Child PID: {child.pid}")
    print("Waiting for the child's HTTPS socket and comparing TCP tables.")

    snapshots = 0
    parsed_rows_seen = 0
    netstat_rows_seen = 0
    printed_netstat = False

    try:
        while child.poll() is None:
            snapshots += 1

            try:
                ipv4 = monitor.get_connections()
                ipv6 = monitor.get_ipv6_connections()
                parsed = [
                    row for row in ipv4 + ipv6 if row["pid"] == child.pid
                ]
            except Exception as exc:
                parsed = []
                print(f"NETTRACK TABLE ERROR: {type(exc).__name__}: {exc}")

            if parsed:
                parsed_rows_seen += len(parsed)
                print(f"\nSNAPSHOT {snapshots}: NETTRACK MATCHES")
                for row in parsed:
                    print(json.dumps(row, sort_keys=True))

            raw_matches, code, error = netstat_rows(child.pid)
            if raw_matches:
                netstat_rows_seen += len(raw_matches)
                if not printed_netstat:
                    print("\nWINDOWS NETSTAT MATCHES:")
                    for line in raw_matches:
                        print(line)
                    printed_netstat = True
            elif snapshots in (2, 6, 10, 14, 18, 22):
                print(
                    f"Snapshot {snapshots}: no netstat row for PID "
                    f"{child.pid}; netstat exit={code}"
                )

            time.sleep(1)

        stdout, stderr = child.communicate(timeout=10)
        print("\nCHILD OUTPUT:")
        print(stdout.strip() or "(no stdout)")
        if stderr.strip():
            print("\nCHILD STDERR:")
            print(stderr.strip())

        print("\nSUMMARY:")
        print(f"Snapshots taken: {snapshots}")
        print(f"NetTrack parser matches: {parsed_rows_seen}")
        print(f"netstat matches: {netstat_rows_seen}")
        if netstat_rows_seen and not parsed_rows_seen:
            print("RESULT: Windows netstat sees the child PID, but NetTrack's")
            print("TCP table parser does not. Investigate table parsing/filters.")
        elif not netstat_rows_seen and not parsed_rows_seen:
            print("RESULT: Neither view found the child PID; inspect the printed")
            print("socket endpoints and verify the child process owns the socket.")
        elif parsed_rows_seen:
            print("RESULT: NetTrack's parser found the child connection.")
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()


if __name__ == "__main__":
    main()
