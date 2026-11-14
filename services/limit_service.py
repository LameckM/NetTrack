
from datetime import datetime, timedelta
from database.db_manager import DatabaseManager


class LimitService:
    def __init__(self, database=None):
        self.db = database or DatabaseManager()

    def get_usage(self, period):
        now = datetime.now().astimezone()

        if period == "daily":
            start = now.replace(
                hour=0, minute=0, second=0, microsecond=0
            )
        elif period == "monthly":
            start = now.replace(
                day=1, hour=0, minute=0, second=0, microsecond=0
            )
        else:
            raise ValueError("Period must be daily or monthly.")

        samples = self.db._get_samples(start)

        downloaded = sum(sample[1] for sample in samples)
        uploaded = sum(sample[2] for sample in samples)

        return downloaded + uploaded

    def set_limit(self, period, limit_mb, enabled=True):
        if period not in ("daily", "monthly"):
            raise ValueError("Period must be daily or monthly.")

        if limit_mb <= 0:
            raise ValueError("Limit must be greater than zero.")

        self.db.save_limit(
            period,
            int(limit_mb * 1024 * 1024),
            enabled
        )

    def check_limit(self, period):
        limit = self.db.get_limit(period)

        if not limit or not limit["enabled"]:
            return None

        used = self.get_usage(period)
        limit_bytes = limit["limit_bytes"]

        percentage = (used / limit_bytes) * 100

        if percentage >= 100:
            status = "exceeded"
        elif percentage >= 80:
            status = "warning"
        else:
            status = "normal"

        return {
            "period": period,
            "used_mb": round(used / (1024 ** 2), 2),
            "limit_mb": round(limit_bytes / (1024 ** 2), 2),
            "percentage": round(percentage, 2),
            "status": status
        }
