
import json
import subprocess
from pathlib import Path

print("Speed test file:", Path(__file__).resolve())
print("Project root:", Path(__file__).resolve().parent.parent)


class SpeedTestService:
    def __init__(self):
        project_root = Path(__file__).resolve().parent.parent
        self.executable = (
            project_root / "tools" / "Ookla" / "speedtest.exe"
        )

    def run_test(self):
        if not self.executable.exists():
            raise FileNotFoundError(
                f"Ookla executable not found: {self.executable}"
            )

        result = subprocess.run(
            [str(self.executable), "--format=json"],
            capture_output=True,
            text=True,
            timeout=180
        )

        if result.returncode != 0:
            raise RuntimeError(
                result.stderr or "Ookla speed test failed."
            )

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError(
                "Could not read Ookla JSON output."
            ) from error

        return {
            "download_mbps": round(
                data["download"]["bandwidth"] * 8 / 1_000_000, 2
            ),
            "upload_mbps": round(
                data["upload"]["bandwidth"] * 8 / 1_000_000, 2
            ),
            "ping_ms": round(data["ping"]["latency"], 2),
            "packet_loss": data.get("packetLoss"),
            "server": data["server"]["name"],
            "isp": data.get("isp"),
            "result_url": data.get("result", {}).get("url"),
            "timestamp": data["timestamp"]
        }
