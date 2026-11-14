
import ctypes
import socket
import time
import psutil
from ctypes import wintypes

iphlpapi = ctypes.WinDLL("iphlpapi")

TCP_TABLE_OWNER_PID_ALL = 5
AF_INET = 2
TCP_ESTATS_DATA = 1


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class MIB_TCPROW(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
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


GetTable = iphlpapi.GetExtendedTcpTable
GetTable.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD),
    wintypes.BOOL, wintypes.ULONG, wintypes.ULONG, wintypes.ULONG
]
GetTable.restype = wintypes.DWORD

SetStats = iphlpapi.SetPerTcpConnectionEStats
SetStats.argtypes = [
    ctypes.POINTER(MIB_TCPROW), wintypes.ULONG,
    ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG, wintypes.ULONG
]
SetStats.restype = wintypes.ULONG

GetStats = iphlpapi.GetPerTcpConnectionEStats
GetStats.argtypes = [
    ctypes.POINTER(MIB_TCPROW), wintypes.ULONG,
    ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG,
    ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG,
    ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG
]
GetStats.restype = wintypes.ULONG


# Retrieve TCP connections.
size = wintypes.DWORD(0)
result = GetTable(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)

if result != 122:
    raise OSError(result, "Could not obtain TCP table size")

buffer = ctypes.create_string_buffer(size.value)
result = GetTable(buffer, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)

if result != 0:
    raise OSError(result, "Could not retrieve TCP table")

count = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value
rows_address = ctypes.addressof(buffer) + 4
rows_type = MIB_TCPROW_OWNER_PID * count
rows = ctypes.cast(rows_address, ctypes.POINTER(rows_type)).contents

# Prefer an established HTTPS connection.
# Select Chrome's established connection.
CHROME_PID = 6984
TARGET_LOCAL_PORT = 56731

selected = next(
    (
        r for r in rows
        if r.dwOwningPid == CHROME_PID
        and r.dwState == 5
        and socket.ntohs(r.dwLocalPort & 0xFFFF)
        == TARGET_LOCAL_PORT
    ),
    None
)

if selected is None:
    raise RuntimeError(
        "Selected Chrome connection no longer exists. "
        "Run the connection discovery test again."
    )

if selected is None:
    raise RuntimeError("No established HTTPS connection found. Open a website and retry.")

row = MIB_TCPROW(
    selected.dwState,
    selected.dwLocalAddr,
    selected.dwLocalPort,
    selected.dwRemoteAddr,
    selected.dwRemotePort,
)

try:
    app_name = psutil.Process(selected.dwOwningPid).name()
except (psutil.NoSuchProcess, psutil.AccessDenied):
    app_name = "Unknown"

print(f"Monitoring: {app_name}")
print(f"PID: {selected.dwOwningPid}")
print(f"Local port: {socket.ntohs(selected.dwLocalPort & 0xFFFF)}")
print("Enabling statistics...")

rw = RW(1)
result = SetStats(
    ctypes.byref(row), TCP_ESTATS_DATA,
    ctypes.byref(rw), 0, ctypes.sizeof(rw), 0
)

if result != 0:
    raise OSError(result, "Could not enable TCP statistics")

def read_counters():
    rw_out = RW()
    rod = ROD()

    result = GetStats(
        ctypes.byref(row), TCP_ESTATS_DATA,
        ctypes.byref(rw_out), 0, ctypes.sizeof(rw_out),
        None, 0, 0,
        ctypes.byref(rod), 0, ctypes.sizeof(rod)
    )

    if result != 0:
        raise OSError(result, "Could not read TCP statistics")

    if not rw_out.EnableCollection:
        raise RuntimeError("TCP statistics collection is disabled")

    return rod.DataBytesOut, rod.DataBytesIn


sent_start, received_start = read_counters()

print("\nMonitoring for 30 seconds.")
print("Refresh a website in the monitored application now.\n")

try:
    for second in range(1, 16):
        time.sleep(2)
        sent, received = read_counters()

        print(
            f"{second * 2:2}s | "
            f"Sent: {sent:,} bytes (+{sent - sent_start:,}) | "
            f"Received: {received:,} bytes (+{received - received_start:,})"
        )

except OSError as error:
    print(f"\nConnection may have closed: {error}")

print("\nMonitoring finished.")
