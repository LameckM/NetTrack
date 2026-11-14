import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.tcp_stats import TCPStatsMonitor

monitor = TCPStatsMonitor()

connections = monitor.get_ipv6_connections()

print("NETTRACK - IPV6 TCP MONITOR")
print("=" * 50)
print("Established IPv6 connections:", len(connections))

for connection in connections:
    print(
        f"PID: {connection['pid']} | "
        f"{connection['local_ip']}:{connection['local_port']} "
        f"-> {connection['remote_ip']}:{connection['remote_port']}"
    )

print("\nIPv6 detection test completed.")