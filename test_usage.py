
from database.db_manager import DatabaseManager

db = DatabaseManager()

totals = db.get_totals()

print("\n===== NETTRACK USAGE REPORT =====")

print("\nALL-TIME USAGE")
print(f"Downloaded: {totals['downloaded_bytes'] / (1024**2):.2f} MB")
print(f"Uploaded: {totals['uploaded_bytes'] / (1024**2):.2f} MB")

print("\nTODAY'S HOURLY USAGE")
for item in db.get_hourly_usage():
    if item["downloaded_bytes"] or item["uploaded_bytes"]:
        print(item)

print("\nLAST 7 DAYS")
for item in db.get_daily_usage():
    print(item)

print("\nLAST 8 WEEKS")
for item in db.get_weekly_usage():
    print(item)

print("\nLAST 12 MONTHS")
for item in db.get_monthly_usage():
    print(item)
