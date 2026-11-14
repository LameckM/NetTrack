
import ctypes
from ctypes import wintypes


def main():
    iphlpapi = ctypes.WinDLL("iphlpapi")
    
    size = wintypes.ULONG(0)
    
    result = iphlpapi.GetPerTcpConnectionEStats(
        None,  # Connection table entry
        0,     # TcpConnectionEstatsData
        None, 0, 0,
        None, 0, 0,
        None, 0, 0
    )
    
    print("Windows API loaded successfully.")
    print("Initial API result:", result)
    

if __name__ == "__main__":
    main()
