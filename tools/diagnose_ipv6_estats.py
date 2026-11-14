import ctypes
import socket
import threading
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.tcp_stats import TCPStatsMonitor, TCP6Row, RW, TCP_ESTATS_DATA, set_stats6

print("Administrator:", bool(ctypes.windll.shell32.IsUserAnAdmin()))
print("TCP6Row size:", ctypes.sizeof(TCP6Row))
print("TCP_ESTATS_DATA:", TCP_ESTATS_DATA)

monitor = TCPStatsMonitor()
server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("::1", 0))
server.listen(1)
server_port = server.getsockname()[1]

accepted = {}

def server_worker():
    conn, _ = server.accept()
    accepted["socket"] = conn
    time.sleep(4)
    conn.close()

thread = threading.Thread(target=server_worker, daemon=True)
thread.start()

client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
client.connect(("::1", server_port))
client_port = client.getsockname()[1]
time.sleep(0.5)

try:
    print("Client port:", client_port, "Server port:", server_port)
    connections = monitor.get_ipv6_connections()

    candidates = [
        c for c in connections
        if {c["local_port"], c["remote_port"]} == {client_port, server_port}
    ]

    print("Matching owner-PID connections:", len(candidates))

    for index, connection in enumerate(candidates, 1):
        print(f"\\nCandidate {index}:", connection)
        try:
            row = monitor.get_ipv6_row(connection)
            print("MIB_TCP6ROW fields:",
                  "local_port_raw=", row.local_port,
                  "remote_port_raw=", row.remote_port,
                  "state=", row.state,
                  "local_scope=", row.local_scope_id,
                  "remote_scope=", row.remote_scope_id)
            rw = RW(1)
            result = set_stats6(
                ctypes.byref(row),
                TCP_ESTATS_DATA,
                ctypes.byref(rw),
                0,
                ctypes.sizeof(rw),
                0,
            )
            print("SetPerTcp6ConnectionEStats return:", result,
                  ctypes.FormatError(result) if result else "SUCCESS")
        except Exception as exc:
            print("Diagnostic error:", repr(exc))
finally:
    client.close()
    server.close()
    thread.join(timeout=5)
