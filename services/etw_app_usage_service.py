"""Background persistence service for real-time ETW application usage."""
import time

from database.db_manager import DatabaseManager
from services.etw_app_monitor import ETWAppMonitor


class ETWAppUsageService:
    def __init__(self, interval=2, monitor=None, database=None):
        if interval <= 0:
            raise ValueError("Collection interval must be greater than zero.")
        self.monitor = monitor or ETWAppMonitor()
        self.database = database or DatabaseManager()
        self.interval = interval

    def collect_once(self):
        applications = self.monitor.collect_once()
        if applications:
            self.database.save_app_usage(applications)
        return applications

    def start(self):
        print("NETTRACK - REAL-TIME APPLICATION USAGE COLLECTOR")
        print("Source: Windows Kernel-Network ETW")
        print(f"Collection interval: {self.interval} seconds")
        print("Press CTRL+C to stop.\n")

        self.monitor.start()
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
        finally:
            self.monitor.stop()

        print("\nSaved application totals:")
        for app in self.database.get_app_totals():
            print(
                f"{app['application']:<25} "
                f"Downloaded: {app['downloaded_mb']:>8.2f} MB | "
                f"Uploaded: {app['uploaded_mb']:>8.2f} MB"
            )
