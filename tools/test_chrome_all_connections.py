
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.tcp_stats import TCPStatsMonitor
import psutil
import time

monitor = TCPStatsMonitor()

previous = {}
enabled = set()

print("Monitoring all Chrome TCP connections.")
print("Refresh a website during the test.\n")

for sample in range(15):

    totals = {
        "sent": 0,
        "received": 0
    }

    connections = monitor.get_connections()

    for connection in connections:

        try:
            process = psutil.Process(connection["pid"])

            if process.name().lower() != "chrome.exe":
                continue

            key = (
                connection["pid"],
                connection["local_ip"],
                connection["local_port"],
                connection["remote_ip"],
                connection["remote_port"]
            )

            if key not in enabled:
                try:
                    monitor.enable_collection(connection)
                    enabled.add(key)
                except OSError:
                    continue

            try:
                counters = monitor.read_counters(connection)
            except (OSError, RuntimeError):
                continue

            current = (
                counters["bytes_sent"],
                counters["bytes_received"]
            )

            if key in previous:
                totals["sent"] += max(0, current[0] - previous[key][0])
                totals["received"] += max(0, current[1] - previous[key][1])

            previous[key] = current

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    print(
        f"Sample {sample + 1:02d} | "
        f"Sent: {totals['sent']:,} B | "
        f"Received: {totals['received']:,} B | "
        f"Connections: {len(enabled)}"
    )

    time.sleep(2)

print("\nMonitoring complete.")
