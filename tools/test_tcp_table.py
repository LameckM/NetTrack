
import ctypes
import socket
from ctypes import wintypes

iphlpapi = ctypes.WinDLL("iphlpapi")


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


GetExtendedTcpTable = iphlpapi.GetExtendedTcpTable
GetExtendedTcpTable.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.BOOL,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.ULONG,
]
GetExtendedTcpTable.restype = wintypes.DWORD

size = wintypes.DWORD(0)

result = GetExtendedTcpTable(
    None, ctypes.byref(size), False, 2, 5, 0
)

if result != 122:
    raise OSError(result, "Could not obtain TCP table size")

buffer = ctypes.create_string_buffer(size.value)

result = GetExtendedTcpTable(
    buffer, ctypes.byref(size), False, 2, 5, 0
)

if result != 0:
    raise OSError(result, "Could not retrieve TCP table")

# Read the number of entries.
count = ctypes.cast(
    buffer,
    ctypes.POINTER(wintypes.DWORD)
).contents.value

# Read all rows immediately after the 4-byte entry count.
rows_address = ctypes.addressof(buffer) + ctypes.sizeof(wintypes.DWORD)

rows_type = MIB_TCPROW_OWNER_PID * count

rows = ctypes.cast(
    rows_address,
    ctypes.POINTER(rows_type)
).contents

print(f"TCP connections found: {count}\n")

for row in rows:
    local_port = socket.ntohs(row.dwLocalPort & 0xFFFF)
    remote_port = socket.ntohs(row.dwRemotePort & 0xFFFF)

    print(
        f"PID: {row.dwOwningPid} | "
        f"State: {row.dwState} | "
        f"Local port: {local_port} | "
        f"Remote port: {remote_port}"
    )
