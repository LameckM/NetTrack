import psutil

from services.tcp_stats import TCPStatsMonitor


class AppMonitor:
    def __init__(self):
        self.tcp_monitor = TCPStatsMonitor()
        self.previous = {}

    def _get_all_connections(self):
        """Return active IPv4 and IPv6 TCP connections."""
        connections = self.tcp_monitor.get_connections()
        connections.extend(self.tcp_monitor.get_ipv6_connections())
        return connections

    def _enable_collection(self, connection):
        if connection.get("family") == "IPv6":
            return self.tcp_monitor.enable_ipv6_collection(connection)
        return self.tcp_monitor.enable_collection(connection)

    def _read_counters(self, connection):
        if connection.get("family") == "IPv6":
            return self.tcp_monitor.read_ipv6_counters(connection)
        return self.tcp_monitor.read_counters(connection)

    def get_usage(self):
        usage = {}
        current_keys = set()

        connections = self._get_all_connections()

        for connection in connections:
            pid = connection["pid"]

            try:
                process = psutil.Process(pid)
                application = process.name()
                process_created = process.create_time()
                family = connection.get("family", "IPv4")

                # Include address family and IPv6 scope IDs so otherwise
                # identical IPv4/IPv6 endpoints cannot collide.
                key = (
                    family,
                    pid,
                    process_created,
                    connection["local_ip"],
                    connection.get("local_scope_id", 0),
                    connection["local_port"],
                    connection["remote_ip"],
                    connection.get("remote_scope_id", 0),
                    connection["remote_port"],
                )
                current_keys.add(key)

                if key not in self.previous:
                    self._enable_collection(connection)
                    self.previous[key] = self._read_counters(connection)
                    continue

                counters = self._read_counters(connection)
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

                # Aggregate all connections belonging to the same process
                # instance, regardless of whether they use IPv4 or IPv6.
                process_key = (application, pid, process_created)

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
