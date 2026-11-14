
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.db_manager import DatabaseManager

db = DatabaseManager()

print("NETTRACK - APPLICATION USAGE SUMMARY")
print("=" * 55)

results = db.get_app_usage_summary()

if not results:
    print("No application usage found.")

for app in results:
    print(f"\nAPPLICATION: {app['application']}")
    print("-" * 55)

    print(f"Total downloaded: {app['downloaded_mb']:.2f} MB")
    print(f"Total uploaded:   {app['uploaded_mb']:.2f} MB")

    print("\nIndividual processes:")

    for process in app["processes"]:
        print(f"\n  PID: {process['pid']}")
        print(f"  Created: {process['process_created']}")
        print(f"  Downloaded: {process['downloaded_mb']:.2f} MB")
        print(f"  Uploaded:   {process['uploaded_mb']:.2f} MB")

print("\nSummary test completed.")
