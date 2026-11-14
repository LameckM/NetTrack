"""Small formatting helpers shared by the NetTrack desktop UI."""


def format_bytes(value):
    value = max(0, float(value or 0))
    units = ("B", "KB", "MB", "GB", "TB")
    amount = value
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            digits = 0 if unit == "B" else 2
            return f"{amount:.{digits}f} {unit}"
        amount /= 1024
    return f"{amount:.2f} TB"


def format_speed(value):
    return f"{max(0, float(value or 0)):.3f} Mbps"
