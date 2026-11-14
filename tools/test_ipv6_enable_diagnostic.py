import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ctypes
from services.tcp_stats import TCPStatsMonitor

monitor = TCPStatsMonitor()
connections = monitor.get_ipv6_connections()

print("IPv6 CONNECTION ENABLE DIAGNOSTIC")
print("=" * 55)

print("TCP6Row size:", ctypes.sizeof(
    __import__("services.tcp_stats", fromlist=["TCP6Row"]).TCP6Row
))

for connection in connections:
    print("\nTesting connection:")
    print("PID:", connection["pid"])
    print("Local:", connection["local_ip"], connection["local_port"])
    print("Remote:", connection["remote_ip"], connection["remote_port"])

    try:
        monitor.enable_ipv6_collection(connection)
        print("PASS: Statistics enabled")
    except OSError as error:
        print("FAIL: Error code:", error.errno)
        print("Message:", error)

print("\nDiagnostic completed.")