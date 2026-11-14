
from datetime import datetime

from services.notification_service import NotificationService
from database.db_manager import DatabaseManager
from services.limit_service import LimitService


class AlertService:
    def __init__(self, database=None):
        self.db = database or DatabaseManager()
        self.limits = LimitService(self.db)
        self.notifications = NotificationService()

    def get_period_start(self, period):
        now = datetime.now().astimezone()

        if period == "daily":
            return now.replace(
                hour=0, minute=0, second=0, microsecond=0
            ).isoformat()

        if period == "monthly":
            return now.replace(
                day=1, hour=0, minute=0,
                second=0, microsecond=0
            ).isoformat()

        raise ValueError("Invalid period")

    def check_alerts(self):
        alerts = []

        for period in ("daily", "monthly"):
            result = self.limits.check_limit(period)

            if result is None:
                continue

            if result["status"] == "exceeded":
                threshold = "exceeded"
            elif result["status"] == "warning":
                threshold = "warning"
            else:
                continue

            period_start = self.get_period_start(period)

            if self.db.has_alert_been_sent(
                period, period_start, threshold
            ):
                continue

            self.db.record_alert(
                period,
                period_start,
                threshold,
                result["used_mb"],
                result["limit_mb"]
            )

            alerts.append({
                "period": period,
                "threshold": threshold,
                "message": (
                    f"{period.capitalize()} data limit "
                    f"{'reached' if threshold == 'exceeded' else 'warning'}: "
                    f"{result['percentage']}% used "
                    f"({result['used_mb']} / {result['limit_mb']} MB)"
                )
            })

            self.notifications.send(
                "NetTrack Data Alert",
                (
                    f"{period.capitalize()} data limit "
                    f"{'reached' if threshold == 'exceeded' else 'warning'}: "
                    f"{result['percentage']}% used "
                    f"({result['used_mb']} / {result['limit_mb']} MB)"
                )
            )

        return alerts
