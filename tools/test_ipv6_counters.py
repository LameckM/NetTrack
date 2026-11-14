
import sys
import time
import socket
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.tcp_stats import TCPStatsMonitor

monitor = TCPStatsMonitor()

server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("::1", 0))
server.listen(1)

port = server.getsockname()[1]

def server_worker():
    connection, _ = server.accept()

    data = connection.recv(1024 * 1024)
    connection.sendall(b"Response from IPv6 server")

    time.sleep(3)
    connection.close()

thread = threading.Thread(target=server_worker)
thread.start()

client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
client.connect(("::1", port))

time.sleep(0.5)

connections = monitor.get_ipv6_connections()

connection = next(
    (
        item for item in connections
        if item["local_port"] == port
        or item["remote_port"] == port
    ),
    None
)

if connection is None:
    raise RuntimeError("Test IPv6 connection was not detected")

print("Detected connection:", connection)

try:
    monitor.enable_ipv6_collection(connection)
    print("PASS: IPv6 statistics enabled")

    first = monitor.read_ipv6_counters(connection)
    print("Initial counters:", first)

    payload = b"X" * (512 * 1024)
    client.sendall(payload)

    response = client.recv(1024)
    print("Server response:", response.decode())

    time.sleep(1)

    second = monitor.read_ipv6_counters(connection)
    print("Updated counters:", second)

    print(
        "Bytes sent increase:",
        second["bytes_sent"] > first["bytes_sent"]
    )

    print(
        "Bytes received increase:",
        second["bytes_received"] > first["bytes_received"]
    )

finally:
    client.close()
    server.close()
    thread.join(timeout=5)

print("IPv6 counter test completed.")
