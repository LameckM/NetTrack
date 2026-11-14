
import ctypes
import ipaddress
import socket


AF_INET6 = 23
TCP_TABLE_OWNER_PID_ALL = 5
ERROR_INSUFFICIENT_BUFFER = 122
MIB_TCP_STATE_ESTAB = 5


class TCP6RowOwnerPID(ctypes.Structure):
    _fields_ = [
        ("local_addr", ctypes.c_ubyte * 16),
        ("local_scope_id", ctypes.c_uint32),
        ("local_port", ctypes.c_uint32),
        ("remote_addr", ctypes.c_ubyte * 16),
        ("remote_scope_id", ctypes.c_uint32),
        ("remote_port", ctypes.c_uint32),
        ("state", ctypes.c_uint32),
        ("pid", ctypes.c_uint32),
    ]


iphlpapi = ctypes.WinDLL("iphlpapi.dll")

get_table = iphlpapi.GetExtendedTcpTable

get_table.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.c_int,
    ctypes.c_uint32,
    ctypes.c_int,
    ctypes.c_uint32,
]

get_table.restype = ctypes.c_uint32


size = ctypes.c_uint32(0)

result = get_table(
    None,
    ctypes.byref(size),
    0,
    AF_INET6,
    TCP_TABLE_OWNER_PID_ALL,
    0,
)

if result not in (ERROR_INSUFFICIENT_BUFFER, 0):
    raise OSError(result, "Failed to get IPv6 TCP table")

if size.value == 0:
    print("No IPv6 TCP table data available.")
    raise SystemExit

buffer = ctypes.create_string_buffer(size.value)

result = get_table(
    buffer,
    ctypes.byref(size),
    0,
    AF_INET6,
    TCP_TABLE_OWNER_PID_ALL,
    0,
)

if result != 0:
    raise OSError(result, "Failed to read IPv6 TCP table")

count = ctypes.cast(
    buffer,
    ctypes.POINTER(ctypes.c_uint32)
).contents.value

offset = ctypes.sizeof(ctypes.c_uint32)

rows = ctypes.cast(
    ctypes.addressof(buffer) + offset,
    ctypes.POINTER(TCP6RowOwnerPID)
)

print(f"IPv6 TCP connections found: {count}")

established = 0

for i in range(count):
    row = rows[i]

    if row.state != MIB_TCP_STATE_ESTAB:
        continue

    established += 1

    local_ip = ipaddress.IPv6Address(bytes(row.local_addr))
    remote_ip = ipaddress.IPv6Address(bytes(row.remote_addr))

    local_port = socket.ntohs(row.local_port & 0xFFFF)
    remote_port = socket.ntohs(row.remote_port & 0xFFFF)

    print(
        f"PID: {row.pid} | "
        f"Local: [{local_ip}]:{local_port} | "
        f"Remote: [{remote_ip}]:{remote_port}"
    )

print(f"\nEstablished IPv6 connections: {established}")
