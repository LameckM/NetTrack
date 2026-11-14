
from winotify import Notification


class NotificationService:
    def send(self, title, message):
        notification = Notification(
            app_id="NetTrack",
            title=title,
            msg=message,
            duration="long"
        )

        notification.show()
