"""Cross-check a live HTTPS socket by local port and identify its owning process.

Run:
    python tools/diagnose_tcp_owner_table.py

The child reports its PID and socket endpoints. The parent checks that exact
local port in netstat, psutil, and NetTrack, then prints process metadata for
the PID Windows assigns to the socket. No EStats calls are made.
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
import os
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
    print("CHILD_PID", os.getpid(), flush=True)
    print("SOCKET_LOCAL", repr(conn.sock.getsockname()), flush=True)
    print("SOCKET_REMOTE", repr(conn.sock.getpeername()), flush=True)
    time.sleep(3)
    conn.request("GET", "/__down?" + urlencode({"bytes": size}))
    response = conn.getresponse()
    payload = response.read()
    print("RESULT", response.status, len(payload), flush=True)
    time.sleep(4)
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


def process_details(pid):
    try:
        process = psutil.Process(pid)
        try:
            cmdline = process.cmdline()
        except (psutil.AccessDenied, psutil.ZombieProcess):
            cmdline = ["<unavailable>"]
        try:
            parent = process.parent()
            parent_info = (
                {"pid": parent.pid, "name": parent.name()}
                if parent else None
            )
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            parent_info = None

        return {
            "pid": pid,
            "name": process.name(),
            "exe": process.exe(),
            "cmdline": cmdline,
            "parent": parent_info,
            "create_time": process.create_time(),
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
        return {"pid": pid, "error": f"{type(exc).__name__}: {exc}"}


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
    print("NETTRACK - TCP SOCKET OWNER PROCESS DIAGNOSTIC")
    print("=" * 68)
    print(f"Popen child PID: {child.pid}")

    local_port = None
    child_output = []
    try:
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
        raw_matches, raw_output, raw_error, code = read_netstat(local_port)

        try:
            psutil_matches = [
                item for item in psutil.net_connections(kind="tcp")
                if item.laddr and item.laddr.port == local_port
            ]
        except Exception as exc:
            psutil_matches = []
            print(f"PSUTIL ERROR: {type(exc).__name__}: {exc}")

        try:
            parsed_rows = (
                monitor.get_connections() + monitor.get_ipv6_connections()
            )
            nettrack_matches = [
                row for row in parsed_rows if row["local_port"] == local_port
            ]
        except Exception as exc:
            nettrack_matches = []
            print(f"NETTRACK TABLE ERROR: {type(exc).__name__}: {exc}")

        print("\nNETSTAT:")
        print("\n".join(raw_matches) if raw_matches else "(none)")

        print("\nPSUTIL:")
        print(json.dumps([
            {
                "pid": item.pid,
                "status": item.status,
                "local": f"{item.laddr.ip}:{item.laddr.port}",
                "remote": (
                    f"{item.raddr.ip}:{item.raddr.port}" if item.raddr else None
                ),
            }
            for item in psutil_matches
        ], indent=2))

        print("\nNETTRACK:")
        print(json.dumps(nettrack_matches, indent=2))

        owner_pids = {
            item.pid for item in psutil_matches if item.pid is not None
        }
        for line in raw_matches:
            fields = line.split()
            if fields and fields[-1].isdigit():
                owner_pids.add(int(fields[-1]))
        for row in nettrack_matches:
            owner_pids.add(row["pid"])

        print("\nPROCESS DETAILS:")
        print("Popen child:", json.dumps(process_details(child.pid), indent=2))
        for pid in sorted(owner_pids):
            print(f"Socket owner {pid}:")
            print(json.dumps(process_details(pid), indent=2))

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
