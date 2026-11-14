
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.db_manager import DatabaseManager

db = DatabaseManager()

print("NETTRACK - PROCESS IDENTITY TEST")
print("=" * 50)

with db.connect() as connection:
    columns = connection.execute(
        "PRAGMA table_info(app_usage_samples)"
    ).fetchall()

    column_names = [column[1] for column in columns]

print("\nDatabase columns:")
for column in column_names:
    print("-", column)

if "process_created" not in column_names:
    print("\nERROR: Migration failed.")
    sys.exit(1)

print("\nSaved process totals:")

for app in db.get_app_process_totals():
    print(f"\nApplication: {app['application']}")
    print(f"PID: {app['pid']}")
    print(f"Process created: {app['process_created']}")
    print(f"Downloaded: {app['downloaded_mb']} MB")
    print(f"Uploaded: {app['uploaded_mb']} MB")

print("\nProcess identity test completed.")
