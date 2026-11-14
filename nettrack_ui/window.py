"""Premium PySide6 desktop dashboard for NetTrack."""
from PySide6.QtCore import QThread, QTimer, Signal, Qt, QPointF
from PySide6.QtGui import QColor, QPainter, QPen, QPainterPath, QLinearGradient
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QFrame, QHBoxLayout, QHeaderView,
    QLabel, QMainWindow, QMessageBox, QPushButton, QScrollArea,
    QStackedWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from core.network_monitor import NetworkMonitor
from database.db_manager import DatabaseManager
from nettrack_ui.formatting import format_bytes, format_speed


class ApplicationMonitorWorker(QThread):
    """Collect ETW application traffic without blocking the interface."""

    status_changed = Signal(str)
    failed = Signal(str)

    def __init__(self, interval=2, parent=None):
        super().__init__(parent)
        self.interval = interval
        self._running = True

    def run(self):
        monitor = None
        try:
            from services.etw_app_monitor import ETWAppMonitor
            monitor = ETWAppMonitor()
            database = DatabaseManager()
            monitor.start()
            self.status_changed.emit("Application monitoring active")
            while self._running:
                applications = monitor.collect_once()
                if applications:
                    database.save_app_usage(applications)
                for _ in range(int(self.interval * 10)):
                    if not self._running:
                        break
                    self.msleep(100)
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            if monitor is not None:
                try:
                    monitor.stop()
                except Exception as exc:
                    self.failed.emit(f"ETW shutdown: {exc}")
            self.status_changed.emit("Application monitoring stopped")

    def stop(self):
        self._running = False


class MetricCard(QFrame):
    def __init__(self, eyebrow, value, caption, accent="blue", parent=None):
        super().__init__(parent)
        self.setObjectName("MetricCard")
        self.setProperty("accent", accent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(7)
        self.eyebrow = QLabel(eyebrow.upper())
        self.eyebrow.setObjectName("Eyebrow")
        self.value = QLabel(value)
        self.value.setObjectName("MetricValue")
        self.caption = QLabel(caption)
        self.caption.setObjectName("MutedText")
        layout.addWidget(self.eyebrow)
        layout.addWidget(self.value)
        layout.addWidget(self.caption)

    def update_value(self, value, caption=None):
        self.value.setText(value)
        if caption is not None:
            self.caption.setText(caption)


class TrafficChart(QWidget):
    """Lightweight custom chart; avoids an extra charting dependency."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.points = []
        self.labels = []
        self.setMinimumHeight(205)

    def set_data(self, points, labels=None):
        self.points = [max(0, float(value or 0)) for value in points]
        self.labels = labels or []
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), QColor("#151f2d"))
        area = self.rect().adjusted(42, 16, -16, -30)
        if area.width() <= 0 or area.height() <= 0:
            return
        grid_pen = QPen(QColor("#29384b"), 1, Qt.PenStyle.DashLine)
        painter.setPen(grid_pen)
        for index in range(4):
            y = area.top() + area.height() * index / 3
            painter.drawLine(int(area.left()), int(y), int(area.right()), int(y))
        if not self.points:
            painter.setPen(QColor("#8493a8"))
            painter.drawText(area, Qt.AlignmentFlag.AlignCenter,
                             "Usage history will appear as data is collected")
            return
        maximum = max(self.points) or 1
        count = len(self.points)
        coords = []
        for index, value in enumerate(self.points):
            x = area.left() + (area.width() * index / max(1, count - 1))
            y = area.bottom() - (value / maximum) * area.height()
            coords.append(QPointF(x, y))
        path = QPainterPath(coords[0])
        for point in coords[1:]:
            path.lineTo(point)
        fill = QPainterPath(path)
        fill.lineTo(coords[-1].x(), area.bottom())
        fill.lineTo(coords[0].x(), area.bottom())
        fill.closeSubpath()
        gradient = QLinearGradient(area.topLeft(), area.bottomLeft())
        gradient.setColorAt(0, QColor(93, 112, 255, 85))
        gradient.setColorAt(1, QColor(93, 112, 255, 3))
        painter.fillPath(fill, gradient)
        painter.setPen(QPen(QColor("#8290ff"), 2.6))
        painter.drawPath(path)
        painter.setBrush(QColor("#a5adff"))
        painter.setPen(Qt.PenStyle.NoPen)
        for point in coords:
            painter.drawEllipse(point, 3.2, 3.2)
        painter.setPen(QColor("#8292a8"))
        if self.labels:
            positions = sorted(set([0, len(self.labels) // 2, len(self.labels) - 1]))
            for index in positions:
                if 0 <= index < len(self.labels):
                    x = area.left() + area.width() * index / max(1, count - 1)
                    painter.drawText(int(x - 35), area.bottom() + 20, 70, 18,
                                     Qt.AlignmentFlag.AlignHCenter,
                                     str(self.labels[index]))


class NetTrackWindow(QMainWindow):
    def __init__(self, monitor=None, database=None):
        super().__init__()
        self.monitor = monitor or NetworkMonitor()
        self.database = database or DatabaseManager()
        self.worker = None
        self.history_period = "7 days"
        self.setWindowTitle("NetTrack | Network Usage Monitor")
        self.setMinimumSize(820, 560)
        self.resize(1180, 680)
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
        self.refresh_history()
        self.start_application_monitoring()

    def _panel(self, title, subtitle=None):
        panel = QFrame()
        panel.setObjectName("Panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)
        heading = QHBoxLayout()
        title_label = QLabel(title)
        title_label.setObjectName("PanelTitle")
        heading.addWidget(title_label)
        heading.addStretch()
        if subtitle:
            meta = QLabel(subtitle)
            meta.setObjectName("MutedText")
            heading.addWidget(meta)
        layout.addLayout(heading)
        return panel, layout

    def _build_ui(self):
        shell = QWidget()
        shell_layout = QHBoxLayout(shell)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(218)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(18, 24, 18, 18)
        side.setSpacing(8)

        brand = QLabel("◈  NetTrack")
        brand.setObjectName("Brand")
        side.addWidget(brand)
        tagline = QLabel("NETWORK INTELLIGENCE")
        tagline.setObjectName("BrandCaption")
        side.addWidget(tagline)
        side.addSpacing(28)
        nav_label = QLabel("WORKSPACE")
        nav_label.setObjectName("NavCaption")
        side.addWidget(nav_label)

        self.nav_buttons = []
        for label, page in (("◫   Overview", 0), ("▤   Applications", 1),
                            ("◷   Usage history", 2)):
            button = QPushButton(label)
            button.setObjectName("NavButton")
            button.setCheckable(True)
            button.clicked.connect(lambda checked=False, p=page: self.show_page(p))
            side.addWidget(button)
            self.nav_buttons.append(button)
        side.addStretch()
        local_note = QLabel("YOUR DATA STAYS LOCAL\nStored securely on this device.")
        local_note.setObjectName("SidebarNote")
        local_note.setWordWrap(True)
        side.addWidget(local_note)

        content_shell = QWidget()
        content_layout = QVBoxLayout(content_shell)
        content_layout.setContentsMargins(26, 20, 26, 18)
        content_layout.setSpacing(18)

        topbar = QHBoxLayout()
        self.page_heading = QLabel("Overview")
        self.page_heading.setObjectName("PageTitle")
        topbar.addWidget(self.page_heading)
        topbar.addStretch()
        self.system_status = QLabel("Connecting…")
        self.system_status.setObjectName("StatusPill")
        topbar.addWidget(self.system_status)
        content_layout.addLayout(topbar)

        self.pages = QStackedWidget()
        self.pages.addWidget(self._scroll_page(self._build_overview_page()))
        self.pages.addWidget(self._scroll_page(self._build_applications_page()))
        self.pages.addWidget(self._scroll_page(self._build_history_page()))
        content_layout.addWidget(self.pages, 1)

        shell_layout.addWidget(sidebar)
        shell_layout.addWidget(content_shell, 1)
        self.setCentralWidget(shell)
        self.show_page(0)

    def _scroll_page(self, content):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(content)
        return scroll

    def _build_overview_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        intro = QLabel("Your connection, at a glance.")
        intro.setObjectName("PageSubtitle")
        layout.addWidget(intro)

        cards = QHBoxLayout()
        cards.setSpacing(12)
        self.download_card = MetricCard("Download speed", "0.000 Mbps",
                                        "Receiving right now", "blue")
        self.upload_card = MetricCard("Upload speed", "0.000 Mbps",
                                      "Sending right now", "violet")
        self.session_card = MetricCard("This session", "0 B",
                                       "Downloaded + uploaded", "cyan")
        self.total_card = MetricCard("Lifetime usage", "0 B",
                                     "All recorded traffic", "green")
        for card in (self.download_card, self.upload_card,
                     self.session_card, self.total_card):
            cards.addWidget(card, 1)
        layout.addLayout(cards)

        chart_panel, chart_layout = self._panel(
            "Network activity", "Daily traffic · last 7 days")
        self.overview_chart = TrafficChart()
        chart_layout.addWidget(self.overview_chart)
        layout.addWidget(chart_panel, 2)

        lower = QHBoxLayout()
        lower.setSpacing(14)
        adapter_panel, adapter_layout = self._panel("Connection details")
        self.adapter_count = QLabel("Scanning adapters…")
        self.adapter_count.setObjectName("MutedText")
        adapter_layout.addWidget(self.adapter_count)
        self.adapter_table = self._make_table(
            ["Network", "Type", "Status", "Down", "Up"])
        adapter_layout.addWidget(self.adapter_table)
        lower.addWidget(adapter_panel, 3)

        top_panel, top_layout = self._panel("Top applications", "By total data")
        self.top_apps_table = self._make_table(["Application", "Downloaded", "Uploaded"])
        top_layout.addWidget(self.top_apps_table)
        lower.addWidget(top_panel, 2)
        layout.addLayout(lower, 2)
        return page

    def _build_applications_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)
        intro = QLabel("See which applications are using your connection.")
        intro.setObjectName("PageSubtitle")
        layout.addWidget(intro)
        panel, panel_layout = self._panel(
            "Application data usage", "Collected in real time on Windows")
        self.app_status = QLabel("Starting application monitor…")
        self.app_status.setObjectName("MutedText")
        panel_layout.addWidget(self.app_status)
        self.app_table = self._make_table(
            ["Application", "Downloaded", "Uploaded", "Total"])
        panel_layout.addWidget(self.app_table)
        layout.addWidget(panel, 1)
        return page

    def _build_history_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)
        intro = QLabel("Understand how your data usage changes over time.")
        intro.setObjectName("PageSubtitle")
        layout.addWidget(intro)
        panel, panel_layout = self._panel("Usage history")
        controls = QHBoxLayout()
        controls.addWidget(QLabel("Time range"))
        self.history_selector = QComboBox()
        self.history_selector.addItems(["24 hours", "7 days", "8 weeks", "12 months"])
        self.history_selector.setCurrentText("7 days")
        self.history_selector.currentTextChanged.connect(self._history_period_changed)
        controls.addWidget(self.history_selector)
        controls.addStretch()
        panel_layout.addLayout(controls)
        self.history_summary = QLabel("Total traffic: —")
        self.history_summary.setObjectName("MutedText")
        panel_layout.addWidget(self.history_summary)
        self.history_chart = TrafficChart()
        panel_layout.addWidget(self.history_chart, 1)
        layout.addWidget(panel, 1)
        return page

    def _make_table(self, headers):
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setShowGrid(False)
        table.setMinimumHeight(150)
        return table

    def _apply_style(self):
        self.setStyleSheet("""
            QMainWindow, QWidget { background: #0e1521; color: #e8edf7;
                font-family: 'Segoe UI'; font-size: 10pt; }
            QFrame#Sidebar { background: #111b2a; border-right: 1px solid #202c40; }
            QLabel#Brand { color: #f7f8ff; font-size: 23px; font-weight: 750; }
            QLabel#BrandCaption, QLabel#NavCaption {
                color: #7788a5; font-size: 9px; font-weight: 700; letter-spacing: 1.5px; }
            QLabel#NavCaption { padding-left: 9px; }
            QPushButton#NavButton { text-align: left; color: #9baac2;
                background: transparent; border: 0; border-radius: 9px;
                padding: 12px 11px; font-size: 10pt; }
            QPushButton#NavButton:hover { background: #1a2940; color: #f2f5ff; }
            QPushButton#NavButton:checked { background: #27345b; color: #b9c4ff;
                font-weight: 650; border-left: 3px solid #8794ff; }
            QLabel#SidebarNote { color: #7788a5; background: #172337;
                border: 1px solid #26344b; border-radius: 10px;
                padding: 12px; font-size: 9px; line-height: 1.5; }
            QLabel#PageTitle { font-size: 24px; font-weight: 700; color: #f5f7ff; }
            QLabel#PageSubtitle { color: #94a3ba; font-size: 11pt; padding-bottom: 2px; }
            QLabel#PanelTitle { color: #f0f3fc; font-size: 13pt; font-weight: 650; }
            QLabel#MutedText { color: #8d9db5; font-size: 9pt; }
            QLabel#Eyebrow { color: #91a1bd; font-size: 9px; font-weight: 700;
                letter-spacing: 1.1px; }
            QLabel#MetricValue { color: #f7f8ff; font-size: 22px; font-weight: 750; }
            QFrame#MetricCard, QFrame#Panel { background: #151f2d;
                border: 1px solid #263449; border-radius: 13px; }
            QLabel#StatusPill { background: #1b3440; color: #7fe0c4;
                border: 1px solid #285b58; border-radius: 12px;
                padding: 7px 12px; font-size: 9pt; }
            QTableWidget { background: #151f2d; alternate-background-color: #192638;
                border: 0; border-radius: 8px; gridline-color: transparent;
                selection-background-color: #2b3c60; }
            QHeaderView::section { background: #1d2a3d; color: #9eacc4;
                padding: 9px; border: 0; font-size: 9px; font-weight: 700; }
            QTableWidget::item { padding: 8px; border-bottom: 1px solid #243247; }
            QComboBox { background: #1b293c; border: 1px solid #30415b;
                border-radius: 7px; padding: 7px 10px; color: #e8edf7; min-width: 110px; }
            QComboBox QAbstractItemView { background: #1b293c; selection-background-color: #34466c; }
            QScrollBar:vertical { background: #111b2a; width: 9px; margin: 0; }
            QScrollBar::handle:vertical { background: #34445e; border-radius: 4px; min-height: 25px; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
        """)

    def show_page(self, index):
        self.pages.setCurrentIndex(index)
        titles = ("Overview", "Applications", "Usage history")
        self.page_heading.setText(titles[index])
        for position, button in enumerate(self.nav_buttons):
            button.setChecked(position == index)
        if index == 2:
            self.refresh_history()

    def refresh_dashboard(self):
        try:
            readings = self.monitor.get_readings()
            active = [item for item in readings
                      if item["connected"] and item["type"] in ("WiFi", "Ethernet")]
            for item in active:
                self.database.save_sample(item)
            downloaded = sum(item.get("session_downloaded", 0) for item in active)
            uploaded = sum(item.get("session_uploaded", 0) for item in active)
            totals = self.database.get_totals()
            self.download_card.update_value(format_speed(
                sum(item["download_mbps"] for item in active)))
            self.upload_card.update_value(format_speed(
                sum(item["upload_mbps"] for item in active)))
            self.session_card.update_value(
                format_bytes(downloaded + uploaded),
                f"↓ {format_bytes(downloaded)}  ·  ↑ {format_bytes(uploaded)}")
            self.total_card.update_value(
                format_bytes(totals["downloaded_bytes"] + totals["uploaded_bytes"]),
                f"↓ {format_bytes(totals['downloaded_bytes'])}  ·  "
                f"↑ {format_bytes(totals['uploaded_bytes'])}")
            self.adapter_count.setText(
                f"{len(active)} active connection(s) · {len(readings)} adapters found")
            self.adapter_table.setRowCount(len(readings))
            for row, item in enumerate(readings):
                values = [
                    item["name"], item["type"],
                    "Connected" if item["connected"] else "Offline",
                    format_speed(item["download_mbps"]),
                    format_speed(item["upload_mbps"]),
                ]
                for col, value in enumerate(values):
                    self.adapter_table.setItem(row, col, QTableWidgetItem(value))
            self.system_status.setText(
                f"{len(active)} connection(s) active" if active else "No active connection")
            self.refresh_overview_chart()
        except Exception as exc:
            self.system_status.setText("Network monitor issue")
            self.statusBar().showMessage(str(exc), 8000)

    def refresh_overview_chart(self):
        try:
            rows = self.database.get_daily_usage(days=7)
            values = [row["downloaded_bytes"] + row["uploaded_bytes"] for row in rows]
            labels = [row["period"][-5:] for row in rows]
            self.overview_chart.set_data(values, labels)
        except Exception as exc:
            self.statusBar().showMessage(f"Could not load traffic chart: {exc}", 8000)

    def refresh_applications(self):
        try:
            applications = self.database.get_app_totals()
            self.app_table.setRowCount(len(applications))
            self.top_apps_table.setRowCount(min(5, len(applications)))
            for row, app in enumerate(applications):
                total = app["downloaded_bytes"] + app["uploaded_bytes"]
                values = [app["application"], format_bytes(app["downloaded_bytes"]),
                          format_bytes(app["uploaded_bytes"]), format_bytes(total)]
                for col, value in enumerate(values):
                    self.app_table.setItem(row, col, QTableWidgetItem(value))
                if row < 5:
                    for col, value in enumerate(values[:3]):
                        self.top_apps_table.setItem(row, col, QTableWidgetItem(value))
        except Exception as exc:
            self.statusBar().showMessage(
                f"Could not load application totals: {exc}", 8000)

    def _history_period_changed(self, period):
        self.history_period = period
        self.refresh_history()

    def refresh_history(self):
        try:
            period = getattr(self, "history_period", "7 days")
            if period == "24 hours":
                rows = self.database.get_hourly_usage()
            elif period == "8 weeks":
                rows = self.database.get_weekly_usage(weeks=8)
            elif period == "12 months":
                rows = self.database.get_monthly_usage(months=12)
            else:
                rows = self.database.get_daily_usage(days=7)
            values = [row["downloaded_bytes"] + row["uploaded_bytes"] for row in rows]
            labels = [row["period"].split()[-1][-5:] for row in rows]
            self.history_chart.set_data(values, labels)
            total = sum(values)
            self.history_summary.setText(
                f"Total traffic in selected period: {format_bytes(total)}")
        except Exception as exc:
            self.statusBar().showMessage(f"Could not load usage history: {exc}", 8000)

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
                    "The application monitor has not stopped yet. Wait before "
                    "forcing the application to close.")
                event.ignore()
                return
        event.accept()
