import ctypes
import socket
import threading
import time
from pathlib import Path
import sys
from ctypes import wintypes

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.tcp_stats import (
    TCPStatsMonitor, TCP6Row, RW, TCP_ESTATS_DATA,
    get_tcp6_table, set_stats6,
)

monitor = TCPStatsMonitor()
server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("::1", 0))
server.listen(1)
server_port = server.getsockname()[1]

def server_worker():
    conn, _ = server.accept()
    time.sleep(5)
    conn.close()

thread = threading.Thread(target=server_worker, daemon=True)
thread.start()

client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
client.connect(("::1", server_port))
client_port = client.getsockname()[1]
time.sleep(0.5)

try:
    connections = monitor.get_ipv6_connections()
    print("Python architecture:", ctypes.sizeof(ctypes.c_void_p) * 8, "bit")
    print("TCP6Row size:", ctypes.sizeof(TCP6Row))
    print("Client/server ports:", client_port, server_port)

    size = wintypes.DWORD(0)
    result = get_tcp6_table(None, ctypes.byref(size), False)
    print("GetTcp6Table size result:", result, "required bytes:", size.value)
    if result != 122:
        raise OSError(result, "GetTcp6Table size query failed")

    buffer = ctypes.create_string_buffer(size.value)
    result = get_tcp6_table(buffer, ctypes.byref(size), False)
    print("GetTcp6Table result:", result)
    if result != 0:
        raise OSError(result, "GetTcp6Table failed")

    count = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value
    print("GetTcp6Table row count:", count)

    targets = [
        c for c in connections
        if {c["local_port"], c["remote_port"]} == {client_port, server_port}
    ]
    print("Owner-PID matching rows:", len(targets))

    for target in targets:
        print("\nOwner-PID candidate:", target)
        matched = False
        for offset in (4, 8):
            if offset + count * ctypes.sizeof(TCP6Row) > size.value:
                continue
            for index in range(count):
                address = ctypes.addressof(buffer) + offset + index * ctypes.sizeof(TCP6Row)
                row_ptr = ctypes.cast(address, ctypes.POINTER(TCP6Row))
                row = row_ptr.contents

                local_ip = socket.inet_ntop(socket.AF_INET6, bytes(row.local_addr))
                remote_ip = socket.inet_ntop(socket.AF_INET6, bytes(row.remote_addr))
                local_port = socket.ntohs(row.local_port & 0xFFFF)
                remote_port = socket.ntohs(row.remote_port & 0xFFFF)

                if (
                    local_ip == target["local_ip"]
                    and remote_ip == target["remote_ip"]
                    and local_port == target["local_port"]
                    and remote_port == target["remote_port"]
                    and row.state == target["state"]
                ):
                    matched = True
                    print("Matched table row at offset", offset, "index", index)
                    print("Row bytes:", bytes(row).hex())
                    rw = RW(1)
                    copied = TCP6Row.from_buffer_copy(bytes(row))
                    copied_result = set_stats6(
                        ctypes.byref(copied), TCP_ESTATS_DATA,
                        ctypes.byref(rw), 0, ctypes.sizeof(rw), 0
                    )
                    print("Set using copied row:", copied_result,
                          ctypes.FormatError(copied_result) if copied_result else "SUCCESS")

                    rw = RW(1)
                    direct_result = set_stats6(
                        row_ptr, TCP_ESTATS_DATA,
                        ctypes.byref(rw), 0, ctypes.sizeof(rw), 0
                    )
                    print("Set using direct table pointer:", direct_result,
                          ctypes.FormatError(direct_result) if direct_result else "SUCCESS")
                    break
            if matched:
                break
        if not matched:
            print("No matching row found in GetTcp6Table for this direction.")
finally:
    client.close()
    server.close()
    thread.join(timeout=6)
