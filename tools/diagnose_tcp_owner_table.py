"""Cross-check a live HTTPS socket by local port, PID, netstat, and psutil.

Run:
    python tools/diagnose_tcp_owner_table.py

The child prints its local socket port before holding the HTTPS connection open.
The parent then checks that exact port in netstat, psutil, and NetTrack's
owner-PID TCP table parser. No EStats calls are made.
"""

import ast
import json
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import psutil
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
    print("SOCKET_LOCAL", repr(conn.sock.getsockname()), flush=True)
    print("SOCKET_REMOTE", repr(conn.sock.getpeername()), flush=True)
    time.sleep(15)
    conn.request("GET", "/__down?" + urlencode({"bytes": size}))
    response = conn.getresponse()
    payload = response.read()
    print("RESULT", response.status, len(payload), flush=True)
    time.sleep(8)
finally:
    conn.close()
"""


def read_netstat(local_port):
    result = subprocess.run(
        ["netstat", "-ano", "-p", "tcp"],
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )
    needle = f":{local_port}"
    matches = [
        line.strip()
        for line in result.stdout.splitlines()
        if needle in line and "TCP" in line.upper()
    ]
    return matches, result.stdout, result.stderr, result.returncode


def main():
    monitor = TCPStatsMonitor()
    child = subprocess.Popen(
        [sys.executable, "-u", "-c", CHILD_CODE, HOST, str(SIZE)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    print("=" * 68)
    print("NETTRACK - TCP SOCKET OWNERSHIP CROSS-CHECK")
    print("=" * 68)
    print(f"Child PID: {child.pid}")

    local_port = None
    child_output = []
    try:
        # Wait for the child to establish its socket and print the local port.
        deadline = time.time() + 20
        while time.time() < deadline and child.poll() is None:
            line = child.stdout.readline()
            if not line:
                continue
            line = line.strip()
            child_output.append(line)
            print(f"CHILD: {line}")
            if line.startswith("SOCKET_LOCAL "):
                endpoint = ast.literal_eval(line[len("SOCKET_LOCAL "):])
                local_port = endpoint[1]
                break

        if local_port is None:
            print("ERROR: Child did not report a local socket port.")
            return

        print(f"\nChecking exact local TCP port: {local_port}")
        netstat_matches = []
        psutil_matches = []
        parsed_matches = []

        for sample in range(1, 11):
            raw_matches, raw_output, raw_error, code = read_netstat(local_port)
            if raw_matches:
                netstat_matches = raw_matches

            try:
                for item in psutil.net_connections(kind="tcp"):
                    if (
                        item.laddr
                        and item.laddr.port == local_port
                    ):
                        psutil_matches.append({
                            "pid": item.pid,
                            "status": item.status,
                            "local": f"{item.laddr.ip}:{item.laddr.port}",
                            "remote": (
                                f"{item.raddr.ip}:{item.raddr.port}"
                                if item.raddr else None
                            ),
                        })
            except Exception as exc:
                print(f"PSUTIL ERROR: {type(exc).__name__}: {exc}")

            try:
                rows = monitor.get_connections() + monitor.get_ipv6_connections()
                parsed_matches = [
                    row for row in rows
                    if row["local_port"] == local_port
                ]
            except Exception as exc:
                print(f"NETTRACK TABLE ERROR: {type(exc).__name__}: {exc}")

            print(
                f"Sample {sample}: netstat={len(netstat_matches)}, "
                f"psutil={len(psutil_matches)}, "
                f"NetTrack={len(parsed_matches)}"
            )
            if netstat_matches or psutil_matches or parsed_matches:
                break
            time.sleep(1)

        print("\nNETSTAT ROWS FOR LOCAL PORT:")
        print("\n".join(netstat_matches) if netstat_matches else "(none)")

        print("\nPSUTIL ROWS FOR LOCAL PORT:")
        print(
            json.dumps(psutil_matches, indent=2)
            if psutil_matches else "(none)"
        )

        print("\nNETTRACK ROWS FOR LOCAL PORT:")
        print(
            json.dumps(parsed_matches, indent=2)
            if parsed_matches else "(none)"
        )

        print("\nRAW NETSTAT ESTABLISHED TCP SAMPLE:")
        established = [
            line.strip()
            for line in raw_output.splitlines()
            if "ESTABLISHED" in line.upper()
        ]
        print("\n".join(established[:15]) if established else "(none)")

        print("\nCHILD OUTPUT:")
        for line in child_output:
            print(line)
        for line in child.stdout:
            line = line.strip()
            if line:
                print(line)
    finally:
        if child.poll() is None:
            child.kill()
        try:
            _, stderr = child.communicate(timeout=10)
            if stderr.strip():
                print("\nCHILD STDERR:")
                print(stderr.strip())
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


if __name__ == "__main__":
    main()
