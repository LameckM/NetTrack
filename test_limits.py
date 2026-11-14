
from services.limit_service import LimitService

limits = LimitService()

# Set a daily limit of 500 MB
limits.set_limit("daily", 500)

# Set a monthly limit of 10 GB
limits.set_limit("monthly", 10240)

print("===== NETTRACK DATA LIMITS =====")

for period in ("daily", "monthly"):
    result = limits.check_limit(period)

    print(f"\n{period.upper()}")

    print(f"Used: {result['used_mb']} MB")
    print(f"Limit: {result['limit_mb']} MB")
    print(f"Usage: {result['percentage']}%")
    print(f"Status: {result['status']}")
