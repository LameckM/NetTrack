
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.tcp_stats import TCPStatsMonitor


def main():
    monitor = TCPStatsMonitor()
    connections = monitor.get_ipv6_connections()
    
    print("IPV6 ROW VALIDATION")
    print("=" * 55)
    
    if not connections:
        print("No established IPv6 connections.")
        raise SystemExit
    
    for connection in connections:
        row = monitor._make_ipv6_row(connection)
    
        print("\nConnection from Windows table:")
        print(connection)
    
        print("\nConstructed MIB_TCP6ROW:")
        print("Local address:", bytes(row.local_addr).hex())
        print("Local scope:", row.local_scope_id)
        print("Local port (raw):", row.local_port)
        print("Remote address:", bytes(row.remote_addr).hex())
        print("Remote scope:", row.remote_scope_id)
        print("Remote port (raw):", row.remote_port)
        print("State:", row.state)
    
        print("\nPort comparison:")
        print("Local expected:", connection["local_port"])
        print("Local constructed:",
              __import__("socket").ntohs(row.local_port & 0xFFFF))
    
        print("Remote expected:", connection["remote_port"])
        print("Remote constructed:",
              __import__("socket").ntohs(row.remote_port & 0xFFFF))
    
    print("\nValidation completed.")
    

if __name__ == "__main__":
    main()
