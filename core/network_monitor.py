
import time
import psutil


class NetworkMonitor:
    def __init__(self):
        self.previous = {}
        self.last_time = None

        self.total_downloaded = {}
        self.total_uploaded = {}

    @staticmethod
    def identify_interface(name):
        value = name.lower()

        if any(x in value for x in ["wi-fi", "wifi", "wireless", "wlan"]):
            return "WiFi"

        if any(x in value for x in ["ethernet", "eth", "enp"]):
            return "Ethernet"

        return "Other"

    def get_readings(self):
        counters = psutil.net_io_counters(pernic=True)
        interfaces = psutil.net_if_stats()

        current_time = time.monotonic()
        

        elapsed = (
            current_time - self.last_time
            if self.last_time is not None
            else 0
        )

        readings = []

        for name, counter in counters.items():
            stats = interfaces.get(name)
            connected = stats.isup if stats else False

            previous = self.previous.get(name)

            download_speed = 0
            upload_speed = 0
            received_delta = 0
            sent_delta = 0
            downloaded_bytes = 0
            uploaded_bytes = 0

            if previous and elapsed > 0:
                received_delta = max(
                    0, counter.bytes_recv - previous["received"]
                )

                sent_delta = max(
                    0, counter.bytes_sent - previous["sent"]
                )

                downloaded_bytes = received_delta
                uploaded_bytes = sent_delta

                download_speed = (
                    received_delta * 8 / elapsed / 1_000_000
                )

                upload_speed = (
                    sent_delta * 8 / elapsed / 1_000_000
                )

                self.total_downloaded[name] = (
                    self.total_downloaded.get(name, 0)
                    + received_delta
                )

                self.total_uploaded[name] = (
                    self.total_uploaded.get(name, 0)
                    + sent_delta
                )

            self.previous[name] = {
                "received": counter.bytes_recv,
                "sent": counter.bytes_sent
            }

            readings.append({
                "name": name,
                "type": self.identify_interface(name),
                "connected": connected,
                "download_mbps": round(download_speed, 3),
                "upload_mbps": round(upload_speed, 3),
                "downloaded_bytes": received_delta,
                "uploaded_bytes": sent_delta,
                "received_bytes": counter.bytes_recv,
                "sent_bytes": counter.bytes_sent,
                "session_downloaded": self.total_downloaded.get(name, 0),
                "session_uploaded": self.total_uploaded.get(name, 0),
                "downloaded_bytes": downloaded_bytes,
                "uploaded_bytes": uploaded_bytes,
            })

        self.last_time = current_time

        return readings
