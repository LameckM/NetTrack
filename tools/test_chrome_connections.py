
import ctypes
import socket
import psutil
from ctypes import wintypes

iphlpapi = ctypes.WinDLL("iphlpapi")

class TCPRow(ctypes.Structure):
    _fields_ = [
        ("state", wintypes.DWORD),
        ("local_addr", wintypes.DWORD),
        ("local_port", wintypes.DWORD),
        ("remote_addr", wintypes.DWORD),
        ("remote_port", wintypes.DWORD),
        ("pid", wintypes.DWORD),
    ]

func = iphlpapi.GetExtendedTcpTable
func.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.BOOL,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.ULONG,
]
func.restype = wintypes.DWORD

size = wintypes.DWORD(0)
result = func(None, ctypes.byref(size), False, 2, 5, 0)

if result != 122:
    raise OSError(result, "Could not get TCP table size")

buffer = ctypes.create_string_buffer(size.value)
result = func(buffer, ctypes.byref(size), False, 2, 5, 0)

if result != 0:
    raise OSError(result, "Could not retrieve TCP table")

count = ctypes.cast(
    buffer, ctypes.POINTER(wintypes.DWORD)
).contents.value

address = ctypes.addressof(buffer) + 4
rows_type = TCPRow * count
rows = ctypes.cast(address, ctypes.POINTER(rows_type)).contents

chrome_pids = {
    p.info["pid"]
    for p in psutil.process_iter(["pid", "name"])
    if (p.info["name"] or "").lower() == "chrome.exe"
}

print("Chrome TCP connections:\n")

found = False

for row in rows:
    if row.pid not in chrome_pids or row.state != 5:
        continue

    local_port = socket.ntohs(row.local_port & 0xFFFF)
    remote_port = socket.ntohs(row.remote_port & 0xFFFF)

    remote_ip = socket.inet_ntoa(
        row.remote_addr.to_bytes(4, "little")
    )

    print(
        f"PID: {row.pid} | "
        f"Local: {local_port} | "
        f"Remote: {remote_ip}:{remote_port}"
    )
    found = True

if not found:
    print("No established Chrome TCP connections found.")
