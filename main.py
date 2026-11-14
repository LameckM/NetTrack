
import time

from core.network_monitor import NetworkMonitor
from database.db_manager import DatabaseManager


monitor = NetworkMonitor()
database = DatabaseManager()

print("=" * 55)
print("              NETTRACK NETWORK MONITOR")
print("=" * 55)

try:
    while True:
        readings = monitor.get_readings()

        print("\n" + "-" * 55)

        for item in readings:
            print(f"\nAdapter: {item['name']}")
            print(f"Type: {item['type']}")
            print(f"Status: {'UP' if item['connected'] else 'DOWN'}")
            print(f"Download: {item['download_mbps']} Mbps")
            print(f"Upload: {item['upload_mbps']} Mbps")

            # Save active WiFi and Ethernet readings
            if item["connected"] and item["type"] in ("WiFi", "Ethernet"):
                database.save_sample(item)

        time.sleep(1)

except KeyboardInterrupt:
    print("\nNetTrack monitoring stopped.")

    totals = database.get_totals()

    print("\nPERMANENTLY SAVED USAGE")
    print(
        f"Downloaded: {totals['downloaded_bytes'] / (1024**2):.2f} MB"
    )
    print(
        f"Uploaded: {totals['uploaded_bytes'] / (1024**2):.2f} MB"
    )
