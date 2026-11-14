
from services.app_monitor import AppMonitor

monitor = AppMonitor()
connections = monitor.get_connections()

print(f"Active TCP connections: {len(connections)}")
print("-" * 60)

for connection in connections:
    print(
        f"Application: {connection['application']} | "
        f"PID: {connection['pid']} | "
        f"Status: {connection['status']}"
    )
