
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.db_manager import DatabaseManager

db = DatabaseManager()

print("NETTRACK - SAVED APPLICATION USAGE")
print("=" * 50)

results = db.get_app_totals()

if not results:
    print("No saved application usage found.")
else:
    for app in results:
        print(f"\nApplication: {app['application']}")
        print(f"Downloaded: {app['downloaded_mb']} MB")
        print(f"Uploaded: {app['uploaded_mb']} MB")

print("\nDaily application usage:")

for app in results:
    print(f"\n{app['application']}")

    daily = db.get_app_daily_usage(
        days=7,
        application=app["application"]
    )

    for day in daily:
        print(
            f"{day['period']} | "
            f"Download: {day['downloaded_mb']} MB | "
            f"Upload: {day['uploaded_mb']} MB"
        )
