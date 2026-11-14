"""Native PySide6 dashboard for NetTrack."""
import time

from PySide6.QtCore import QThread, QTimer, Signal, Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.network_monitor import NetworkMonitor
from database.db_manager import DatabaseManager
from nettrack_ui.formatting import format_bytes, format_speed


class ApplicationMonitorWorker(QThread):
    """Run ETW collection away from the GUI thread."""

    status_changed = Signal(str)
    failed = Signal(str)

    def __init__(self, interval=2, parent=None):
        super().__init__(parent)
        self.interval = interval
        self._running = True

    def run(self):
        from services.etw_app_monitor import ETWAppMonitor

        monitor = ETWAppMonitor()
        try:
            monitor.start()
            self.status_changed.emit("Application monitoring active")
            while self._running:
                applications = monitor.collect_once()
                if applications:
                    DatabaseManager().save_app_usage(applications)
                # Wait in short increments so shutdown remains responsive.
                for _ in range(int(self.interval * 10)):
                    if not self._running:
                        break
                    self.msleep(100)
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            try:
                monitor.stop()
            except Exception as exc:
                self.failed.emit(f"ETW shutdown: {exc}")
            self.status_changed.emit("Application monitoring stopped")

    def stop(self):
        self._running = False


class MetricCard(QFrame):
    def __init__(self, title, value="—", detail="", parent=None):
        super().__init__(parent)
        self.setObjectName("MetricCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 14)
        self.heading = QLabel(title.upper())
        self.heading.setObjectName("MetricHeading")
        self.value = QLabel(value)
        self.value.setObjectName("MetricValue")
        self.detail = QLabel(detail)
        self.detail.setObjectName("MetricDetail")
        layout.addWidget(self.heading)
        layout.addWidget(self.value)
        layout.addWidget(self.detail)

    def update_value(self, value, detail=None):
        self.value.setText(value)
        if detail is not None:
            self.detail.setText(detail)


class NetTrackWindow(QMainWindow):
    def __init__(self, monitor=None, database=None):
        super().__init__()
        self.monitor = monitor or NetworkMonitor()
        self.database = database or DatabaseManager()
        self.worker = None
        self.setWindowTitle("NetTrack | Network Usage Monitor")
        self.resize(1180, 760)
        self._build_ui()
        self._apply_style()

        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_dashboard)
        self.refresh_timer.start(1000)

        self.app_refresh_timer = QTimer(self)
        self.app_refresh_timer.timeout.connect(self.refresh_applications)
        self.app_refresh_timer.start(3000)

        self.refresh_dashboard()
        self.refresh_applications()
        self.start_application_monitoring()

    def _build_ui(self):
        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(28, 22, 28, 22)
        root_layout.setSpacing(18)

        header = QHBoxLayout()
        brand = QVBoxLayout()
        title = QLabel("NetTrack")
        title.setObjectName("AppTitle")
        subtitle = QLabel("NETWORK USAGE MONITOR")
        subtitle.setObjectName("AppSubtitle")
        brand.addWidget(title)
        brand.addWidget(subtitle)
        header.addLayout(brand)
        header.addStretch()
        self.system_status = QLabel("Starting monitors…")
        self.system_status.setObjectName("StatusPill")
        header.addWidget(self.system_status, alignment=Qt.AlignVCenter)
        root_layout.addLayout(header)

        section = QLabel("Network overview")
        section.setObjectName("SectionTitle")
        root_layout.addWidget(section)

        cards = QHBoxLayout()
        cards.setSpacing(14)
        self.download_card = MetricCard("Download speed", "0.000 Mbps", "Current")
        self.upload_card = MetricCard("Upload speed", "0.000 Mbps", "Current")
        self.session_card = MetricCard("Session usage", "0 B", "Downloaded / uploaded")
        self.total_card = MetricCard("All-time usage", "0 B", "Downloaded / uploaded")
        for card in (self.download_card, self.upload_card,
                     self.session_card, self.total_card):
            cards.addWidget(card)
        root_layout.addLayout(cards)

        adapter_header = QHBoxLayout()
        adapter_title = QLabel("Network adapters")
        adapter_title.setObjectName("SectionTitle")
        self.adapter_count = QLabel("0 adapters")
        self.adapter_count.setObjectName("MutedText")
        adapter_header.addWidget(adapter_title)
        adapter_header.addStretch()
        adapter_header.addWidget(self.adapter_count)
        root_layout.addLayout(adapter_header)

        self.adapter_table = QTableWidget(0, 6)
        self.adapter_table.setHorizontalHeaderLabels(
            ["Adapter", "Type", "Status", "Download", "Upload", "Session total"]
        )
        self.adapter_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.adapter_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.adapter_table.verticalHeader().setVisible(False)
        self.adapter_table.horizontalHeader().setStretchLastSection(True)
        self.adapter_table.setMinimumHeight(190)
        root_layout.addWidget(self.adapter_table)

        app_header = QHBoxLayout()
        app_title = QLabel("Application usage")
        app_title.setObjectName("SectionTitle")
        self.app_status = QLabel("Waiting for ETW")
        self.app_status.setObjectName("MutedText")
        app_header.addWidget(app_title)
        app_header.addStretch()
        app_header.addWidget(self.app_status)
        root_layout.addLayout(app_header)

        self.app_table = QTableWidget(0, 4)
        self.app_table.setHorizontalHeaderLabels(
            ["Application", "Downloaded", "Uploaded", "Total"]
        )
        self.app_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.app_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.app_table.verticalHeader().setVisible(False)
        self.app_table.horizontalHeader().setStretchLastSection(True)
        self.app_table.setMinimumHeight(190)
        root_layout.addWidget(self.app_table)

        footer = QLabel(
            "Historical totals are stored locally in SQLite. "
            "Per-application monitoring requires Windows and Administrator privileges."
        )
        footer.setObjectName("Footer")
        footer.setWordWrap(True)
        root_layout.addWidget(footer)
        self.setCentralWidget(root)

    def _apply_style(self):
        self.setStyleSheet("""
            QMainWindow, QWidget { background: #101722; color: #e8eef7; }
            QLabel#AppTitle { font-size: 29px; font-weight: 700; color: #f4f7fb; }
            QLabel#AppSubtitle { color: #8493a8; font-size: 10px; letter-spacing: 2px; }
            QLabel#SectionTitle { font-size: 17px; font-weight: 650; color: #f0f4fa; }
            QLabel#MutedText, QLabel#Footer { color: #91a0b4; font-size: 11px; }
            QLabel#Footer { padding-top: 5px; }
            QLabel#StatusPill { background: #1b3540; color: #7ce0c0;
                border: 1px solid #285c58; border-radius: 12px;
                padding: 7px 12px; font-size: 11px; }
            QFrame#MetricCard { background: #192433; border: 1px solid #29384b;
                border-radius: 12px; }
            QLabel#MetricHeading { color: #94a4b9; font-size: 10px;
                font-weight: 650; letter-spacing: 1px; }
            QLabel#MetricValue { color: #f5f8fc; font-size: 22px; font-weight: 700; }
            QLabel#MetricDetail { color: #8292a8; font-size: 10px; }
            QTableWidget { background: #172231; alternate-background-color: #1b2939;
                border: 1px solid #29384b; border-radius: 9px;
                gridline-color: #29384b; selection-background-color: #294b66; }
            QHeaderView::section { background: #202e3f; color: #aebdd0;
                padding: 10px; border: none; font-size: 10px; font-weight: 650; }
            QTableWidget::item { padding: 8px; border-bottom: 1px solid #263447; }
        """)

    def refresh_dashboard(self):
        try:
            readings = self.monitor.get_readings()
            active = [
                item for item in readings
                if item["connected"] and item["type"] in ("WiFi", "Ethernet")
            ]
            for item in active:
                self.database.save_sample(item)

            downloaded = sum(x.get("session_downloaded", 0) for x in active)
            uploaded = sum(x.get("session_uploaded", 0) for x in active)
            totals = self.database.get_totals()

            down_speed = sum(x["download_mbps"] for x in active)
            up_speed = sum(x["upload_mbps"] for x in active)
            self.download_card.update_value(format_speed(down_speed))
            self.upload_card.update_value(format_speed(up_speed))
            self.session_card.update_value(
                f"{format_bytes(downloaded + uploaded)}",
                f"↓ {format_bytes(downloaded)}  /  ↑ {format_bytes(uploaded)}"
            )
            self.total_card.update_value(
                format_bytes(totals["downloaded_bytes"] + totals["uploaded_bytes"]),
                f"↓ {format_bytes(totals['downloaded_bytes'])}  /  "
                f"↑ {format_bytes(totals['uploaded_bytes'])}"
            )
            self.adapter_count.setText(f"{len(readings)} adapters detected")
            self.adapter_table.setRowCount(len(readings))
            for row, item in enumerate(readings):
                status = "Connected" if item["connected"] else "Disconnected"
                session_total = (
                    item.get("session_downloaded", 0)
                    + item.get("session_uploaded", 0)
                )
                values = [
                    item["name"], item["type"], status,
                    format_speed(item["download_mbps"]),
                    format_speed(item["upload_mbps"]),
                    format_bytes(session_total),
                ]
                for col, value in enumerate(values):
                    self.adapter_table.setItem(row, col, QTableWidgetItem(value))
            self.system_status.setText(
                f"{len(active)} active network adapter(s)"
            )
        except Exception as exc:
            self.system_status.setText("Network monitor error")
            self.statusBar().showMessage(str(exc), 8000)

    def refresh_applications(self):
        try:
            applications = self.database.get_app_totals()
            self.app_table.setRowCount(len(applications))
            for row, app in enumerate(applications):
                total = app["downloaded_bytes"] + app["uploaded_bytes"]
                values = [
                    app["application"],
                    format_bytes(app["downloaded_bytes"]),
                    format_bytes(app["uploaded_bytes"]),
                    format_bytes(total),
                ]
                for col, value in enumerate(values):
                    self.app_table.setItem(row, col, QTableWidgetItem(value))
        except Exception as exc:
            self.statusBar().showMessage(
                f"Could not load application totals: {exc}", 8000
            )

    def start_application_monitoring(self):
        self.worker = ApplicationMonitorWorker(parent=self)
        self.worker.status_changed.connect(self.app_status.setText)
        self.worker.failed.connect(self._show_monitor_error)
        self.worker.start()

    def _show_monitor_error(self, message):
        self.app_status.setText("Application monitoring unavailable")
        self.statusBar().showMessage(message, 12000)

    def closeEvent(self, event):
        self.refresh_timer.stop()
        self.app_refresh_timer.stop()
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            if not self.worker.wait(12000):
                QMessageBox.warning(
                    self, "NetTrack is still stopping",
                    "The ETW monitor has not stopped yet. Please wait before "
                    "forcing the application to close."
                )
                event.ignore()
                return
        event.accept()
