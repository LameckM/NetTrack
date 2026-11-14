
import time

from services.app_monitor import AppMonitor
from database.db_manager import DatabaseManager


class AppUsageService:
    def __init__(self, interval=2):
        self.monitor = AppMonitor()
        self.database = DatabaseManager()
        self.interval = interval

    def collect_once(self):
        applications = self.monitor.get_usage()

        if applications:
            self.database.save_app_usage(applications)

        return applications

    def start(self):
        print("NETTRACK - APPLICATION USAGE COLLECTOR")
        print(f"Collection interval: {self.interval} seconds")
        print("Press CTRL+C to stop.\n")

        try:
            while True:
                applications = self.collect_once()

                for app in applications:
                    print(
                        f"{app['application']:<25} "
                        f"Download: {app['bytes_received']:>10,} B | "
                        f"Upload: {app['bytes_sent']:>10,} B"
                    )

                time.sleep(self.interval)

        except KeyboardInterrupt:
            print("\nApplication monitoring stopped.")

            print("\nSaved application totals:")

            for app in self.database.get_app_totals():
                print(
                    f"{app['application']:<25} "
                    f"Downloaded: {app['downloaded_mb']:>8.2f} MB | "
                    f"Uploaded: {app['uploaded_mb']:>8.2f} MB"
                )
