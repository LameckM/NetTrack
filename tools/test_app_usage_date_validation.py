import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.db_manager import DatabaseManager

db = DatabaseManager()

try:
    db.get_app_usage_summary(
        start_date="2026-11-15",
        end_date="2026-11-13"
    )
except ValueError as error:
    print("PASS:", error)
else:
    print("FAIL: Invalid date range was accepted.")

try:
    db.get_app_usage_summary(start_date="2026-13-40")
except ValueError:
    print("PASS: Invalid date format rejected.")
else:
    print("FAIL: Invalid date was accepted.")