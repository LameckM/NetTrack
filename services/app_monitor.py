
import psutil

from services.tcp_stats import TCPStatsMonitor


class AppMonitor:
    def __init__(self):
        self.tcp_monitor = TCPStatsMonitor()
        self.previous = {}

    def get_usage(self):
        usage = {}
        current_keys = set()

        connections = self.tcp_monitor.get_connections()

        for connection in connections:
            pid = connection["pid"]

            try:
                process = psutil.Process(pid)

                application = process.name()
                process_created = process.create_time()

                # Identify each connection using its process instance
                # and network endpoints.
                key = (
                    pid,
                    process_created,
                    connection["local_ip"],
                    connection["local_port"],
                    connection["remote_ip"],
                    connection["remote_port"],
                )

                current_keys.add(key)

                if key not in self.previous:
                    self.tcp_monitor.enable_collection(connection)

                    counters = self.tcp_monitor.read_counters(connection)

                    # Establish baseline for new connections.
                    self.previous[key] = counters
                    continue

                counters = self.tcp_monitor.read_counters(connection)
                previous = self.previous[key]

                sent = max(
                    0,
                    counters["bytes_sent"] - previous["bytes_sent"]
                )

                received = max(
                    0,
                    counters["bytes_received"] - previous["bytes_received"]
                )

                self.previous[key] = counters

                # Keep separate records for individual process instances.
                process_key = (
                    application,
                    pid,
                    process_created
                )

                if process_key not in usage:
                    usage[process_key] = {
                        "pid": pid,
                        "application": application,
                        "process_created": process_created,
                        "bytes_sent": 0,
                        "bytes_received": 0,
                        "total_bytes": 0,
                    }

                usage[process_key]["bytes_sent"] += sent
                usage[process_key]["bytes_received"] += received
                usage[process_key]["total_bytes"] += sent + received

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                OSError,
                RuntimeError,
            ):
                continue

        # Remove connections that are no longer active.
        self.previous = {
            key: value
            for key, value in self.previous.items()
            if key in current_keys
        }

        return sorted(
            usage.values(),
            key=lambda item: item["total_bytes"],
            reverse=True,
        )
