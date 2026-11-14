import time

from services.app_monitor import AppMonitor


def main():
    monitor = AppMonitor()

    print("=" * 60)
    print("NETTRACK APPLICATION USAGE MONITOR")
    print("=" * 60)
    print("Sampling active IPv4 and IPv6 TCP connections for 5 seconds...")
    print("Keep applications active (for example, browse the web) during this test.")
    print()

    # First poll enables statistics and establishes baselines.
    first_connections = monitor._get_all_connections()
    print(f"Active TCP connections detected: {len(first_connections)}")
    print(
        "IPv4:",
        sum(1 for item in first_connections if item.get("family") != "IPv6"),
    )
    print(
        "IPv6:",
        sum(1 for item in first_connections if item.get("family") == "IPv6"),
    )

    monitor.get_usage()
    time.sleep(5)

    usage = monitor.get_usage()

    print("\nAPPLICATION TRAFFIC (bytes transferred during the sample)")
    print("-" * 60)

    if not usage:
        print("No measurable traffic found.")
        print("Keep an application actively transferring data and run again.")
        return

    for item in usage:
        print(
            f"{item['application']} (PID {item['pid']}) | "
            f"Download/Received: {item['bytes_received']:,} bytes | "
            f"Upload/Sent: {item['bytes_sent']:,} bytes | "
            f"Total: {item['total_bytes']:,} bytes"
        )

    print("\nPASS: Live application usage sampling completed.")


if __name__ == "__main__":
    main()
