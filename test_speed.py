
from services.speed_test import SpeedTestService

service = SpeedTestService()

print("Running NetTrack speed test...")
print("This may take a minute.\n")

try:
    result = service.run_test()

    print("===== NETTRACK SPEED TEST =====")
    print(f"Download: {result['download_mbps']} Mbps")
    print(f"Upload: {result['upload_mbps']} Mbps")
    print(f"Ping: {result['ping_ms']} ms")
    print(f"Packet loss: {result['packet_loss']}%")
    print(f"Server: {result['server']}")
    print(f"ISP: {result['isp']}")
    print(f"Result: {result['result_url']}")

except Exception as error:
    print(f"Speed test failed: {error}")
