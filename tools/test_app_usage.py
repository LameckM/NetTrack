
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.app_monitor import AppMonitor
import time


monitor = AppMonitor()

print("NETTRACK - PER APPLICATION USAGE")
print("Refresh websites or download something during the test.\n")

for sample in range(15):
    time.sleep(2)

    results = monitor.get_usage()

    print(f"\n--- Sample {sample + 1}/15 ---")

    if not results:
        print("No new traffic detected.")
        continue

    for app in results:
        print(
            f"{app['application']:<25} "
            f"Sent: {app['bytes_sent']:>10,} B | "
            f"Received: {app['bytes_received']:>10,} B | "
            f"Total: {app['total_bytes']:>10,} B"
        )

print("\nMonitoring complete.")
