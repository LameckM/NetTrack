
import ctypes
import socket
from ctypes import wintypes


iphlpapi = ctypes.WinDLL("iphlpapi")

AF_INET = 2
AF_INET6 = 23
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

class TCP6RowPID(ctypes.Structure):
    _fields_ = [
        ("local_addr", ctypes.c_ubyte * 16),
        ("local_scope_id", wintypes.DWORD),
        ("local_port", wintypes.DWORD),
        ("remote_addr", ctypes.c_ubyte * 16),
        ("remote_scope_id", wintypes.DWORD),
        ("remote_port", wintypes.DWORD),
        ("state", wintypes.DWORD),
        ("pid", wintypes.DWORD),
    ]


class TCP6Row(ctypes.Structure):
    _fields_ = [
        ("local_addr", ctypes.c_ubyte * 16),
        ("local_scope_id", wintypes.DWORD),
        ("local_port", wintypes.DWORD),
        ("remote_addr", ctypes.c_ubyte * 16),
        ("remote_scope_id", wintypes.DWORD),
        ("remote_port", wintypes.DWORD),
        ("state", wintypes.DWORD),
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

get_tcp6_table = iphlpapi.GetTcp6Table

get_tcp6_table.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.BOOL,
]

get_tcp6_table.restype = wintypes.DWORD


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

set_stats6 = iphlpapi.SetPerTcp6ConnectionEStats
set_stats6.argtypes = [
    ctypes.POINTER(TCP6Row),
    wintypes.ULONG,
    ctypes.c_void_p,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.ULONG,
]
set_stats6.restype = wintypes.ULONG


get_stats6 = iphlpapi.GetPerTcp6ConnectionEStats
get_stats6.argtypes = [
    ctypes.POINTER(TCP6Row),
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
get_stats6.restype = wintypes.ULONG


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


class TCPStatsMonitor:

    def get_connections(self):
        size = wintypes.DWORD(0)

        result = get_table(
            None,
            ctypes.byref(size),
            False,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )

        if result != 122:
            raise OSError(result, "Could not obtain TCP table size")

        buffer = ctypes.create_string_buffer(size.value)

        result = get_table(
            buffer,
            ctypes.byref(size),
            False,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )

        if result != 0:
            raise OSError(result, "Could not retrieve TCP table")

        count = ctypes.cast(
            buffer,
            ctypes.POINTER(wintypes.DWORD),
        ).contents.value

        address = ctypes.addressof(buffer) + 4
        rows_type = TCPRowPID * count

        rows = ctypes.cast(
            address,
            ctypes.POINTER(rows_type),
        ).contents

        connections = []

        for item in rows:
            if item.state != 5 or item.pid == 0:
                continue

            connections.append({
                "pid": item.pid,
                "local_ip": socket.inet_ntoa(
                    item.local_addr.to_bytes(4, "little")
                ),
                "local_port": socket.ntohs(
                    item.local_port & 0xFFFF
                ),
                "remote_ip": socket.inet_ntoa(
                    item.remote_addr.to_bytes(4, "little")
                ),
                "remote_port": socket.ntohs(
                    item.remote_port & 0xFFFF
                ),
                "state": item.state,
            })

        return connections

    def _make_row(self, connection):
        return TCPRow(
            connection["state"],
            int.from_bytes(
                socket.inet_aton(connection["local_ip"]), "little"
            ),
            socket.htons(connection["local_port"]),
            int.from_bytes(
                socket.inet_aton(connection["remote_ip"]), "little"
            ),
            socket.htons(connection["remote_port"]),
        )

    def enable_collection(self, connection):
        row = self._make_row(connection)
        rw = RW(1)

        result = set_stats(
            ctypes.byref(row),
            TCP_ESTATS_DATA,
            ctypes.byref(rw),
            0,
            ctypes.sizeof(rw),
            0,
        )

        if result != 0:
            raise OSError(result, "Could not enable TCP statistics")

        return True

    def read_counters(self, connection):
        row = self._make_row(connection)
        rw = RW()
        rod = ROD()

        result = get_stats(
            ctypes.byref(row),
            TCP_ESTATS_DATA,
            ctypes.byref(rw),
            0,
            ctypes.sizeof(rw),
            None,
            0,
            0,
            ctypes.byref(rod),
            0,
            ctypes.sizeof(rod),
        )

        if result != 0:
            raise OSError(result, "Could not read TCP statistics")

        if not rw.EnableCollection:
            raise RuntimeError("TCP statistics collection is disabled")

        return {
            "bytes_sent": rod.DataBytesOut,
            "bytes_received": rod.DataBytesIn,
        }
    def get_ipv6_connections(self):
        size = wintypes.DWORD(0)

        result = get_table(
            None,
            ctypes.byref(size),
            False,
            AF_INET6,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )

        if result != 122:
            raise OSError(
                result,
                "Could not obtain IPv6 TCP table size"
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
            raise OSError(
                result,
                "Could not retrieve IPv6 TCP table"
            )

        count = ctypes.cast(
            buffer,
            ctypes.POINTER(wintypes.DWORD)
        ).contents.value

        address = ctypes.addressof(buffer) + 4

        rows_type = TCP6RowPID * count

        rows = ctypes.cast(
            address,
            ctypes.POINTER(rows_type)
        ).contents

        connections = []

        for item in rows:
            if item.state != 5 or item.pid == 0:
                continue

            connections.append({
                "pid": item.pid,
                "local_ip": socket.inet_ntop(
                    socket.AF_INET6,
                    bytes(item.local_addr)
                ),
                "local_scope_id": item.local_scope_id,
                "local_port": socket.ntohs(
                    item.local_port & 0xFFFF
                ),
                "remote_ip": socket.inet_ntop(
                    socket.AF_INET6,
                    bytes(item.remote_addr)
                ),
                "remote_scope_id": item.remote_scope_id,
                "remote_port": socket.ntohs(
                    item.remote_port & 0xFFFF
                ),
                "state": item.state,
                "family": "IPv6",
            })

        return connections

    def _make_ipv6_row(self, connection):
        row = TCP6Row()

        row.local_addr = (
            ctypes.c_ubyte * 16
        ).from_buffer_copy(
            socket.inet_pton(
                socket.AF_INET6,
                connection["local_ip"]
            )
        )

        row.local_scope_id = connection["local_scope_id"]
        row.local_port = socket.htons(connection["local_port"])

        row.remote_addr = (
            ctypes.c_ubyte * 16
        ).from_buffer_copy(
            socket.inet_pton(
                socket.AF_INET6,
                connection["remote_ip"]
            )
        )

        row.remote_scope_id = connection["remote_scope_id"]
        row.remote_port = socket.htons(connection["remote_port"])
        row.state = connection["state"]

        return row

    def enable_ipv6_collection(self, connection):
        row = self.get_ipv6_row(connection)
        rw = RW(1)

        result = set_stats6(
            ctypes.byref(row),
            TCP_ESTATS_DATA,
            ctypes.byref(rw),
            0,
            ctypes.sizeof(rw),
            0,
        )

        if result != 0:
            raise OSError(
                result,
                "Could not enable IPv6 TCP statistics"
            )

        return True

    def read_ipv6_counters(self, connection):
        row = self._make_ipv6_row(connection)
        rw = RW()
        rod = ROD()

        result = get_stats6(
            ctypes.byref(row),
            TCP_ESTATS_DATA,
            ctypes.byref(rw),
            0,
            ctypes.sizeof(rw),
            None,
            0,
            0,
            ctypes.byref(rod),
            0,
            ctypes.sizeof(rod),
        )

        if result != 0:
            raise OSError(
                result,
                "Could not read IPv6 TCP statistics"
            )

        if not rw.EnableCollection:
            raise RuntimeError(
                "IPv6 TCP statistics collection is disabled"
            )

        return {
            "bytes_sent": rod.DataBytesOut,
            "bytes_received": rod.DataBytesIn,
        }

    def get_ipv6_row(self, connection):
        # SetPerTcp6ConnectionEStats requires a row from GetTcp6Table.
        # Do not construct it from the owner-PID table snapshot: retrieve
        # the canonical MIB_TCP6ROW currently registered by Windows.
        size = wintypes.DWORD(0)

        result = get_tcp6_table(None, ctypes.byref(size), False)
        if result != 122:
            raise OSError(result, "Could not obtain IPv6 TCP table size")

        buffer = ctypes.create_string_buffer(size.value)
        result = get_tcp6_table(buffer, ctypes.byref(size), False)
        if result != 0:
            raise OSError(result, "Could not retrieve IPv6 TCP table")

        count = ctypes.cast(
            buffer, ctypes.POINTER(wintypes.DWORD)
        ).contents.value

        wanted_local = socket.inet_pton(socket.AF_INET6, connection["local_ip"])
        wanted_remote = socket.inet_pton(socket.AF_INET6, connection["remote_ip"])

        # Microsoft documents that MIB_TCP6TABLE may include padding after
        # dwNumEntries. Try the documented DWORD boundary and the 8-byte
        # aligned boundary, accepting only a row matching the full tuple.
        offsets = (ctypes.sizeof(wintypes.DWORD), 8)
        for offset in offsets:
            required_size = offset + count * ctypes.sizeof(TCP6Row)
            if required_size > size.value:
                continue

            rows_type = TCP6Row * count
            rows = ctypes.cast(
                ctypes.addressof(buffer) + offset,
                ctypes.POINTER(rows_type),
            ).contents

            for row in rows:
                if (
                    bytes(row.local_addr) == wanted_local
                    and bytes(row.remote_addr) == wanted_remote
                    and row.local_scope_id == connection["local_scope_id"]
                    and row.remote_scope_id == connection["remote_scope_id"]
                    and socket.ntohs(row.local_port & 0xFFFF) == connection["local_port"]
                    and socket.ntohs(row.remote_port & 0xFFFF) == connection["remote_port"]
                    and row.state == connection["state"]
                ):
                    return TCP6Row.from_buffer_copy(bytes(row))

        raise RuntimeError(
            "IPv6 connection from GetExtendedTcpTable was not found "
            "in GetTcp6Table at either supported table-row alignment; "
            "the connection may have closed or changed"
        )