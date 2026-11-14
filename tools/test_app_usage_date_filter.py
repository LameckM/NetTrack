import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.db_manager import DatabaseManager

db = DatabaseManager()

def print_summary(title, results):
    print(f"\n{title}")
    print("=" * 55)

    if not results:
        print("No application usage found.")
        return

    for app in results:
        print(
            f"{app['application']}: "
            f"Downloaded {app['downloaded_mb']:.2f} MB | "
            f"Uploaded {app['uploaded_mb']:.2f} MB"
        )

print_summary(
    "ALL-TIME USAGE",
    db.get_app_usage_summary()
)

print_summary(
    "USAGE ON 2026-11-13",
    db.get_app_usage_summary(
        start_date="2026-11-13",
        end_date="2026-11-13"
    )
)

print_summary(
    "USAGE FROM 2026-11-13 ONWARD",
    db.get_app_usage_summary(
        start_date="2026-11-13"
    )
)

print_summary(
    "USAGE UP TO 2026-11-13",
    db.get_app_usage_summary(
        end_date="2026-11-13"
    )
)

print("\nDate filter test completed.")