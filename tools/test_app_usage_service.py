
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.app_usage_service import AppUsageService


service = AppUsageService(interval=2)

service.start()
