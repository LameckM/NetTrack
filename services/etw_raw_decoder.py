"""Selective decoder for raw Microsoft-Windows-Kernel-Network ETW records.

Raw records avoid pywintrace's full TDH payload decoding. This decoder asks
TDH for only the payload PID and size fields required for application usage.
"""
import ctypes as ct
import ctypes.wintypes as wt

from services.etw_event_accounting import (
    RECEIVE_EVENT_IDS,
    SEND_EVENT_IDS,
)

MAX_UINT = 0xFFFFFFFF
ERROR_SUCCESS = 0
TRAFFIC_EVENT_IDS = sorted(SEND_EVENT_IDS | RECEIVE_EVENT_IDS)


def create_provider_parameters(etw_impl):
    """Filter at the ETW provider to the traffic event IDs NetTrack uses."""
    event_filter = etw_impl.ep.EVENT_FILTER_EVENT_ID(
        True, TRAFFIC_EVENT_IDS
    )
    filter_size = (
        ct.sizeof(etw_impl.ep.EVENT_FILTER_EVENT_ID)
        + len(TRAFFIC_EVENT_IDS) * ct.sizeof(ct.c_ushort)
    )
    descriptor = etw_impl.ep.EVENT_FILTER_DESCRIPTOR(
        ct.addressof(event_filter._buf),
        filter_size,
        etw_impl.ep.EVENT_FILTER_TYPE_EVENT_ID,
    )
    parameters = etw_impl.ProviderParameters(0, [descriptor])

    # The provider session retains pointers to this descriptor. Keep both the
    # descriptor buffer and event filter alive for the session's lifetime.
    descriptor_buffer = (ct.c_char * ct.sizeof(
        etw_impl.ep.EVENT_FILTER_DESCRIPTOR
    ))()
    ct.memmove(
        ct.addressof(descriptor_buffer),
        ct.byref(descriptor),
        ct.sizeof(etw_impl.ep.EVENT_FILTER_DESCRIPTOR),
    )
    parameters._descriptor_buffer = descriptor_buffer
    parameters._event_filter = event_filter
    parameters._props.contents.EnableFilterDesc = ct.cast(
        ct.pointer(descriptor_buffer),
        ct.POINTER(etw_impl.ep.EVENT_FILTER_DESCRIPTOR),
    )
    parameters._props.contents.FilterDescCount = 1
    return parameters


class RawKernelNetworkEventDecoder:
    """Decode only PID and size from a raw ETW EVENT_RECORD."""

    def __init__(self, etw_impl, tdh):
        self._etw_impl = etw_impl
        self._tdh = tdh
        self._schemas = {}

    def _schema_for(self, record, event_id):
        version = int(record.contents.EventHeader.EventDescriptor.Version)
        key = (event_id, version)
        cached = self._schemas.get(key)
        if cached is not None:
            return cached

        info = self._etw_impl.EventConsumer._getEventInformation(record)
        base = ct.cast(info, ct.c_void_p).value
        properties = ct.cast(
            info.contents.EventPropertyInfoArray,
            ct.POINTER(self._tdh.EVENT_PROPERTY_INFO),
        )
        offsets = {}
        for index in range(info.contents.TopLevelPropertyCount):
            prop = properties[index]
            name = ct.wstring_at(base + prop.NameOffset).lower()
            if name in {"pid", "size"}:
                offsets[name] = int(prop.NameOffset)

        if set(offsets) != {"pid", "size"}:
            raise ValueError(
                f"Kernel-Network event {event_id} v{version} does not "
                f"contain PID and size fields (found {sorted(offsets)})"
            )

        schema = (
            info,
            self._tdh.PROPERTY_DATA_DESCRIPTOR(
                base + offsets["pid"], MAX_UINT, 0
            ),
            self._tdh.PROPERTY_DATA_DESCRIPTOR(
                base + offsets["size"], MAX_UINT, 0
            ),
        )
        self._schemas[key] = schema
        return schema

    def _read_uint(self, record, descriptor):
        size = wt.ULONG()
        status = self._tdh.TdhGetPropertySize(
            record, 0, None, 1, ct.byref(descriptor), ct.byref(size)
        )
        if status != ERROR_SUCCESS:
            raise OSError(status, "TdhGetPropertySize failed")
        if size.value not in (1, 2, 4, 8):
            raise ValueError(
                f"Unexpected integer property width: {size.value}"
            )

        buffer = (ct.c_byte * size.value)()
        status = self._tdh.TdhGetProperty(
            record,
            0,
            None,
            1,
            ct.byref(descriptor),
            size.value,
            ct.cast(buffer, ct.POINTER(ct.c_byte)),
        )
        if status != ERROR_SUCCESS:
            raise OSError(status, "TdhGetProperty failed")
        return int.from_bytes(bytes(buffer), "little", signed=False)

    def decode(self, record, event_id):
        if event_id not in SEND_EVENT_IDS | RECEIVE_EVENT_IDS:
            return None
        _info, pid_descriptor, size_descriptor = self._schema_for(
            record, event_id
        )
        pid = self._read_uint(record, pid_descriptor)
        size = self._read_uint(record, size_descriptor)
        if pid <= 0 or size < 0:
            return None
        return {"PID": pid, "size": size}
