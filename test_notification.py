
from services.notification_service import NotificationService

notifications = NotificationService()

notifications.send(
    "NetTrack",
    "Your daily data usage has reached 80%."
)

print("Notification sent!")
