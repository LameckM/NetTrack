
import ctypes
import socket
import time
import psutil
from collections import defaultdict
from ctypes import wintypes

iphlpapi = ctypes.WinDLL("iphlpapi")

AF_INET = 2
TCP_TABLE_OWNER_PID_ALL = 5
TCP_ESTATS_DATA = 1


class TCPRowPID(ctypes.Structure):
    _fields_ = [
        ("state", wintypes.DWORD),
        ("local_addr", wintypes.DWORD),
        ("local_port", wintypes.DWORD),
        ("remote_addr", wintypes.DWORD),
        ("remote_port", wintypes.DWORD),
        ("pid", wintypes.DWORD),
    ]


class TCPRow(ctypes.Structure):
    _fields_ = [
        ("state", wintypes.DWORD),
        ("local_addr", wintypes.DWORD),
        ("local_port", wintypes.DWORD),
        ("remote_addr", wintypes.DWORD),
        ("remote_port", wintypes.DWORD),
    ]


class RW(ctypes.Structure):
    _fields_ = [("EnableCollection", ctypes.c_ubyte)]


class ROD(ctypes.Structure):
    _fields_ = [
        ("DataBytesOut", ctypes.c_uint64),
        ("DataSegsOut", ctypes.c_uint64),
        ("DataBytesIn", ctypes.c_uint64),
        ("DataSegsIn", ctypes.c_uint64),
        ("SegsOut", ctypes.c_uint64),
        ("SegsIn", ctypes.c_uint64),
        ("SoftErrors", wintypes.DWORD),
        ("SoftErrorReason", wintypes.DWORD),
        ("SndUna", wintypes.DWORD),
        ("SndNxt", wintypes.DWORD),
        ("SndMax", wintypes.DWORD),
        ("ThruBytesAcked", ctypes.c_uint64),
        ("RcvNxt", wintypes.DWORD),
        ("ThruBytesReceived", ctypes.c_uint64),
    ]


get_table = iphlpapi.GetExtendedTcpTable
get_table.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.BOOL,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.ULONG,
]
get_table.restype = wintypes.DWORD

set_stats = iphlpapi.SetPerTcpConnectionEStats
set_stats.argtypes = [
    ctypes.POINTER(TCPRow),
    wintypes.ULONG,
    ctypes.c_void_p,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.ULONG,
]
set_stats.restype = wintypes.ULONG

get_stats = iphlpapi.GetPerTcpConnectionEStats
get_stats.argtypes = [
    ctypes.POINTER(TCPRow),
    wintypes.ULONG,
    ctypes.c_void_p,
    wintypes.ULONG,
    wintypes.ULONG,
    ctypes.c_void_p,
    wintypes.ULONG,
    wintypes.ULONG,
    ctypes.c_void_p,
    wintypes.ULONG,
    wintypes.ULONG,
]
get_stats.restype = wintypes.ULONG


def get_tcp_connections():
    size = wintypes.DWORD(0)

    result = get_table(
        None, ctypes.byref(size), False,
        AF_INET, TCP_TABLE_OWNER_PID_ALL, 0
    )

    if result != 122:
        raise OSError(result, "Could not obtain TCP table size")

    buffer = ctypes.create_string_buffer(size.value)

    result = get_table(
        buffer, ctypes.byref(size), False,
        AF_INET, TCP_TABLE_OWNER_PID_ALL, 0
    )

    if result != 0:
        raise OSError(result, "Could not retrieve TCP table")

    count = ctypes.cast(
        buffer, ctypes.POINTER(wintypes.DWORD)
    ).contents.value

    address = ctypes.addressof(buffer) + 4
    rows_type = TCPRowPID * count

    return ctypes.cast(
        address, ctypes.POINTER(rows_type)
    ).contents


def connection_key(r):
    return (
        r.pid,
        r.local_addr,
        r.local_port,
        r.remote_addr,
        r.remote_port,
    )


def make_api_row(r):
    return TCPRow(
        r.state,
        r.local_addr,
        r.local_port,
        r.remote_addr,
        r.remote_port,
    )


def read_counters(row):
    rw = RW()
    rod = ROD()

    result = get_stats(
        ctypes.byref(row), TCP_ESTATS_DATA,
        ctypes.byref(rw), 0, ctypes.sizeof(rw),
        None, 0, 0,
        ctypes.byref(rod), 0, ctypes.sizeof(rod),
    )

    if result != 0 or not rw.EnableCollection:
        return None

    return rod.DataBytesOut, rod.DataBytesIn


def enable_collection(row):
    rw = RW(1)

    result = set_stats(
        ctypes.byref(row), TCP_ESTATS_DATA,
        ctypes.byref(rw), 0, ctypes.sizeof(rw), 0,
    )

    return result == 0



def main():
    previous = {}
    enabled = set()
    
    print("Monitoring all established IPv4 TCP connections.")
    print("Duration: 30 seconds\n")
    
    for cycle in range(15):
        usage = defaultdict(lambda: [0, 0])
    
        try:
            connections = get_tcp_connections()
        except OSError as error:
            print("TCP table error:", error)
            break
    
        for connection in connections:
            if connection.state != 5 or connection.pid == 0:
                continue
    
            key = connection_key(connection)
            row = make_api_row(connection)
    
            if key not in enabled:
                if not enable_collection(row):
                    continue
                enabled.add(key)
    
            counters = read_counters(row)
    
            if counters is None:
                continue
    
            sent, received = counters
    
            if key in previous:
                old_sent, old_received = previous[key]
    
                sent_delta = max(0, sent - old_sent)
                received_delta = max(0, received - old_received)
    
                try:
                    process_name = psutil.Process(
                        connection.pid
                    ).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_name = "Unknown"
    
                usage[process_name][0] += sent_delta
                usage[process_name][1] += received_delta
    
            previous[key] = (sent, received)
    
        print(f"\n--- Sample {cycle + 1}/15 ---")
    
        if not usage:
            print("No new traffic detected.")
    
        for name, totals in sorted(
            usage.items(),
            key=lambda item: sum(item[1]),
            reverse=True,
        ):
            print(
                f"{name:25} "
                f"Sent: {totals[0]:>10,} B | "
                f"Received: {totals[1]:>10,} B"
            )
    
        time.sleep(2)
    
    print("\nMonitoring complete.")
    

if __name__ == "__main__":
    main()
