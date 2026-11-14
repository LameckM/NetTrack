"""Controlled diagnostic for traffic on short-lived versus persistent TCP connections.

Run from the repository root on Windows:
    python tools/diagnose_short_lived_connections.py

This is a diagnostic, not a pass/fail unit test. It compares known application
payload bytes sent by a child process with bytes observed by AppMonitor.
"""

import socket
import subprocess
import sys
import threading
import time

from services.app_monitor import AppMonitor


HOST = "127.0.0.1"
POLL_INTERVAL = 2.0
PAYLOAD_SIZE = 16 * 1024
RESPONSE_SIZE = 8 * 1024
BURST_CONNECTIONS = 40
LONG_CONNECTION_HOLD_SECONDS = 5.0

CLIENT_CODE = r"""
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
mode = sys.argv[3]
payload_size = int(sys.argv[4])
response_size = int(sys.argv[5])
count = int(sys.argv[6])
hold_seconds = float(sys.argv[7])

payload = b"C" * payload_size
expected_response = response_size

if mode == "persistent":
    with socket.create_connection((host, port), timeout=10) as client:
        client.sendall(payload)
        received = 0
        while received < expected_response:
            chunk = client.recv(expected_response - received)
            if not chunk:
                raise RuntimeError("Server closed before sending the full response")
            received += len(chunk)
        time.sleep(hold_seconds)
else:
    for _ in range(count):
        with socket.create_connection((host, port), timeout=10) as client:
            client.sendall(payload)
            received = 0
            while received < expected_response:
                chunk = client.recv(expected_response - received)
                if not chunk:
                    raise RuntimeError("Server closed before sending the full response")
                received += len(chunk)
    # Keep the process alive after all sockets have closed so the monitor
    # can take its next scheduled sample and identify the target PID.
    time.sleep(hold_seconds)
"""


class LocalTrafficServer:
    def __init__(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((HOST, 0))
        self.listener.listen()
        self.listener.settimeout(0.5)
        self.port = self.listener.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while self.running:
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            with connection:
                received = 0
                while received < PAYLOAD_SIZE:
                    chunk = connection.recv(PAYLOAD_SIZE - received)
                    if not chunk:
                        break
                    received += len(chunk)

                if received == PAYLOAD_SIZE:
                    connection.sendall(b"S" * RESPONSE_SIZE)

    def close(self):
        self.running = False
        self.listener.close()
        self.thread.join(timeout=1)


def usage_for_pid(monitor, pid):
    rows = monitor.get_usage()
    for row in rows:
        if row["pid"] == pid:
            return row["bytes_sent"], row["bytes_received"]
    return 0, 0


def run_phase(monitor, server, mode, count, hold_seconds):
    # Establish a clean baseline before the child process opens connections.
    monitor.get_usage()

    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            CLIENT_CODE,
            HOST,
            str(server.port),
            mode,
            str(PAYLOAD_SIZE),
            str(RESPONSE_SIZE),
            str(count),
            str(hold_seconds),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )

    measured_sent = 0
    measured_received = 0
    samples = max(3, int(hold_seconds / POLL_INTERVAL) + 2)

    for _ in range(samples):
        time.sleep(POLL_INTERVAL)
        sent, received = usage_for_pid(monitor, process.pid)
        measured_sent += sent
        measured_received += received

    _, stderr = process.communicate(timeout=10)
    if process.returncode != 0:
        raise RuntimeError(
            f"Traffic generator failed (exit {process.returncode}): {stderr}"
        )

    expected_sent = PAYLOAD_SIZE if mode == "persistent" else PAYLOAD_SIZE * count
    expected_received = RESPONSE_SIZE if mode == "persistent" else RESPONSE_SIZE * count

    return {
        "pid": process.pid,
        "expected_sent": expected_sent,
        "expected_received": expected_received,
        "measured_sent": measured_sent,
        "measured_received": measured_received,
    }


def print_result(label, result):
    print(f"\n{label}")
    print("-" * len(label))
    print(f"Target process PID: {result['pid']}")
    print(f"Expected upload:   {result['expected_sent']:,} bytes")
    print(f"Observed upload:   {result['measured_sent']:,} bytes")
    print(f"Expected download: {result['expected_received']:,} bytes")
    print(f"Observed download: {result['measured_received']:,} bytes")

    sent_gap = max(0, result["expected_sent"] - result["measured_sent"])
    received_gap = max(0, result["expected_received"] - result["measured_received"])
    print(f"Upload not observed:   {sent_gap:,} bytes")
    print(f"Download not observed: {received_gap:,} bytes")


def main():
    print("=" * 64)
    print("NETTRACK - SHORT-LIVED TCP CONNECTION DIAGNOSTIC")
    print("=" * 64)
    print(f"Sampling interval: {POLL_INTERVAL:.0f} seconds")
    print("Traffic is sent only over the local loopback interface.")
    print("No internet traffic is generated.")

    server = LocalTrafficServer()
    monitor = AppMonitor()

    try:
        print("\nRunning persistent-connection control...")
        persistent = run_phase(
            monitor,
            server,
            mode="persistent",
            count=1,
            hold_seconds=LONG_CONNECTION_HOLD_SECONDS,
        )
        print_result("PERSISTENT CONNECTION CONTROL", persistent)

        print("\nRunning short-lived connection burst...")
        burst = run_phase(
            monitor,
            server,
            mode="burst",
            count=BURST_CONNECTIONS,
            hold_seconds=LONG_CONNECTION_HOLD_SECONDS,
        )
        print_result("SHORT-LIVED CONNECTION BURST", burst)

        print("\nDiagnostic complete. These results measure this machine and run;")
        print("they are not a guarantee of accuracy for every application.")
    finally:
        server.close()


if __name__ == "__main__":
    main()
