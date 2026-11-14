import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.tcp_stats import TCPStatsMonitor
import psutil
import time

monitor = TCPStatsMonitor()

connections = monitor.get_connections()

if not connections:
    print("No established TCP connections found.")
    raise SystemExit

# Prefer a Chrome connection if one exists.
connection = next(
    (
        item for item in connections
        if psutil.Process(item["pid"]).name().lower() == "chrome.exe"
    ),
    connections[0]
)

process = psutil.Process(connection["pid"])

print("Application:", process.name())
print("PID:", connection["pid"])
print("Local port:", connection["local_port"])

try:
    monitor.enable_collection(connection)
    print("\nTCP statistics collection enabled.")

    print("\nOpen or refresh a website in the monitored application.")

    for i in range(10):
        time.sleep(2)

        counters = monitor.read_counters(connection)

        print(
            f"{(i + 1) * 2:2}s | "
            f"Sent: {counters['bytes_sent']:,} bytes | "
            f"Received: {counters['bytes_received']:,} bytes"
        )

except (OSError, RuntimeError, psutil.Error) as error:
    print("Monitoring error:", error)
