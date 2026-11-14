
import tempfile
import gc
from pathlib import Path

from database.db_manager import DatabaseManager
from services.alert_service import AlertService


folder = tempfile.mkdtemp()
db = None

try:
    db = DatabaseManager(Path(folder) / "test.db")

    db.save_limit("daily", 500 * 1024 * 1024, True)
    db.save_limit("monthly", 10 * 1024 * 1024 * 1024, True)

    def add_usage(download_mb):
        db.save_sample({
            "name": "Wi-Fi",
            "type": "WiFi",
            "downloaded_bytes": int(download_mb * 1024 * 1024),
            "uploaded_bytes": 0,
            "download_mbps": 0,
            "upload_mbps": 0
        })

    alerts = AlertService(db)

    add_usage(410)
    print("\nFIRST CHECK (82%)")
    print(alerts.check_alerts())

    print("\nSECOND CHECK (same usage)")
    print(alerts.check_alerts())

    add_usage(100)
    print("\nTHIRD CHECK (102%)")
    print(alerts.check_alerts())

finally:
    db = None
    alerts = None
    gc.collect()

    import shutil
    shutil.rmtree(folder, ignore_errors=True)
