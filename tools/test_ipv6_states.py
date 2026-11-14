
import ctypes
from ctypes import wintypes
import socket

iphlpapi = ctypes.WinDLL("iphlpapi.dll")

AF_INET6 = 23
TCP_TABLE_OWNER_PID_ALL = 5

class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("LocalAddr", ctypes.c_ubyte * 16),
        ("LocalScopeId", wintypes.DWORD),
        ("LocalPort", wintypes.DWORD),
        ("RemoteAddr", ctypes.c_ubyte * 16),
        ("RemoteScopeId", wintypes.DWORD),
        ("RemotePort", wintypes.DWORD),
        ("State", wintypes.DWORD),
        ("OwningPid", wintypes.DWORD),
    ]

class MIB_TCP6TABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwNumEntries", wintypes.DWORD),
        ("table", MIB_TCP6ROW_OWNER_PID * 1),
    ]

get_table = iphlpapi.GetExtendedTcpTable
get_table.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.BOOL,
    wintypes.ULONG,
    ctypes.c_int,
    wintypes.ULONG,
]
get_table.restype = wintypes.DWORD

size = wintypes.DWORD(0)

get_table(
    None,
    ctypes.byref(size),
    False,
    AF_INET6,
    TCP_TABLE_OWNER_PID_ALL,
    0,
)

buffer = ctypes.create_string_buffer(size.value)

result = get_table(
    buffer,
    ctypes.byref(size),
    False,
    AF_INET6,
    TCP_TABLE_OWNER_PID_ALL,
    0,
)

if result != 0:
    raise OSError(result, "GetExtendedTcpTable failed")

table = ctypes.cast(
    buffer,
    ctypes.POINTER(MIB_TCP6TABLE_OWNER_PID)
).contents

print("IPv6 TCP CONNECTION STATES")
print("=" * 50)
print("Total connections:", table.dwNumEntries)

rows_address = (
    ctypes.addressof(buffer)
    + MIB_TCP6TABLE_OWNER_PID.table.offset
)

rows = ctypes.cast(
    rows_address,
    ctypes.POINTER(MIB_TCP6ROW_OWNER_PID)
)

states = {
    1: "CLOSED",
    2: "LISTEN",
    3: "SYN_SENT",
    4: "SYN_RECEIVED",
    5: "ESTABLISHED",
    6: "FIN_WAIT_1",
    7: "FIN_WAIT_2",
    8: "CLOSE_WAIT",
    9: "CLOSING",
    10: "LAST_ACK",
    11: "TIME_WAIT",
    12: "DELETE_TCB",
}

for i in range(table.dwNumEntries):
    row = rows[i]

    local_ip = socket.inet_ntop(
        socket.AF_INET6,
        bytes(row.LocalAddr)
    )

    remote_ip = socket.inet_ntop(
        socket.AF_INET6,
        bytes(row.RemoteAddr)
    )

    local_port = socket.ntohs(row.LocalPort & 0xFFFF)
    remote_port = socket.ntohs(row.RemotePort & 0xFFFF)

    print(
        f"State: {states.get(row.State, row.State)} | "
        f"PID: {row.OwningPid} | "
        f"{local_ip}:{local_port} -> "
        f"{remote_ip}:{remote_port}"
    )
