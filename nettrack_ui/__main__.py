"""Launch the NetTrack desktop dashboard with: python -m nettrack_ui"""

import sys

from PySide6.QtWidgets import QApplication

from nettrack_ui.window import NetTrackWindow


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("NetTrack")
    window = NetTrackWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
