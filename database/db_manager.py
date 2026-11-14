
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta


class DatabaseManager:
    def __init__(self, db_path=None):
        if db_path is None:
            project_root = Path(__file__).resolve().parent.parent
            db_path = project_root / "data" / "nettrack.db"

        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.create_tables()

    def connect(self):
        connection = sqlite3.connect(self.db_path)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def create_tables(self):
        with self.connect() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS usage_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    interface_name TEXT NOT NULL,
                    interface_type TEXT NOT NULL,
                    download_bytes INTEGER NOT NULL DEFAULT 0,
                    upload_bytes INTEGER NOT NULL DEFAULT 0,
                    download_mbps REAL NOT NULL DEFAULT 0,
                    upload_mbps REAL NOT NULL DEFAULT 0
                )
            """)

            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_usage_timestamp
                ON usage_samples(timestamp)
            """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS data_limits (
                period TEXT PRIMARY KEY,
                limit_bytes INTEGER NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1
                )
            """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS alert_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    period TEXT NOT NULL,
                    period_start TEXT NOT NULL,
                    threshold TEXT NOT NULL,
                    used_mb REAL NOT NULL,
                    limit_mb REAL NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(period, period_start, threshold)
                )
        """)

            
            connection.execute("""
                CREATE TABLE IF NOT EXISTS app_usage_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    process_id INTEGER NOT NULL,
                    process_created REAL,
                    application TEXT NOT NULL,
                    download_bytes INTEGER NOT NULL DEFAULT 0,
                    upload_bytes INTEGER NOT NULL DEFAULT 0
                )
            """)

            # Safely add process_created to existing databases.
            columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(app_usage_samples)"
                ).fetchall()
            }

            if "process_created" not in columns:
                connection.execute("""
                    ALTER TABLE app_usage_samples
                    ADD COLUMN process_created REAL
                """)

            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_app_usage_timestamp
                ON app_usage_samples(timestamp)
            """)

            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_app_usage_application
                ON app_usage_samples(application)
            """)


    def save_sample(self, reading):
        timestamp = datetime.now().astimezone().isoformat()

        with self.connect() as connection:
            connection.execute("""
                INSERT INTO usage_samples (
                    timestamp, interface_name, interface_type,
                    download_bytes, upload_bytes,
                    download_mbps, upload_mbps
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp,
                reading["name"],
                reading["type"],
                reading.get("downloaded_bytes", 0),
                reading.get("uploaded_bytes", 0),
                reading["download_mbps"],
                reading["upload_mbps"]
            ))

    def save_app_usage(self, applications):
        timestamp = datetime.now().astimezone().isoformat()

        with self.connect() as connection:
            connection.executemany("""
                INSERT INTO app_usage_samples (
                    timestamp,
                    process_id,
                    process_created,
                    application,
                    download_bytes,
                    upload_bytes
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, [
                (
                    timestamp,
                    app["pid"],
                    app["process_created"],
                    app["application"],
                    app["bytes_received"],
                    app["bytes_sent"]
                )
                for app in applications
                if app["bytes_received"] > 0 or app["bytes_sent"] > 0
            ])


    def get_totals(self, interface_name=None):
        query = """
            SELECT
                COALESCE(SUM(download_bytes), 0),
                COALESCE(SUM(upload_bytes), 0)
            FROM usage_samples
        """
        params = ()

        if interface_name:
            query += " WHERE interface_name = ?"
            params = (interface_name,)

        with self.connect() as connection:
            result = connection.execute(query, params).fetchone()

        return {
            "downloaded_bytes": result[0],
            "uploaded_bytes": result[1]
        }

    def _get_samples(self, start_time, interface_name=None):
        query = """
            SELECT timestamp, download_bytes, upload_bytes
            FROM usage_samples
            WHERE timestamp >= ?
        """
        params = [start_time.isoformat()]

        if interface_name:
            query += " AND interface_name = ?"
            params.append(interface_name)

        query += " ORDER BY timestamp"

        with self.connect() as connection:
            return connection.execute(query, params).fetchall()

    @staticmethod
    def _format_usage(downloaded, uploaded):
        return {
            "downloaded_bytes": downloaded,
            "uploaded_bytes": uploaded,
            "downloaded_mb": round(downloaded / (1024 ** 2), 2),
            "uploaded_mb": round(uploaded / (1024 ** 2), 2)
        }

    def _aggregate(self, start_time, bucket_function,
                   label_function, count, interface_name=None):
        now = datetime.now().astimezone()
        samples = self._get_samples(start_time, interface_name)

        buckets = {}

        for i in range(count):
            bucket_time = bucket_function(now, i)
            buckets[label_function(bucket_time)] = [0, 0]

        for timestamp, downloaded, uploaded in samples:
            sample_time = datetime.fromisoformat(timestamp).astimezone()
            label = label_function(bucket_function(sample_time, 0))

            if label in buckets:
                buckets[label][0] += downloaded
                buckets[label][1] += uploaded

        return [
            {
                "period": label,
                **self._format_usage(values[0], values[1])
            }
            for label, values in buckets.items()
        ]

    def get_hourly_usage(self, interface_name=None):
        now = datetime.now().astimezone()
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)

        return self._aggregate(
            start,
            lambda dt, i: (dt.replace(minute=0, second=0, microsecond=0)
                           - timedelta(hours=i)),
            lambda dt: dt.strftime("%Y-%m-%d %H:00"),
            24,
            interface_name
        )

    def get_daily_usage(self, days=7, interface_name=None):
        now = datetime.now().astimezone()
        today = now.replace(hour=0, minute=0, second=0, microsecond=0)
        start = today - timedelta(days=days - 1)

        return self._aggregate(
            start,
            lambda dt, i: (
                dt.replace(hour=0, minute=0, second=0, microsecond=0)
                - timedelta(days=i)
            ),
            lambda dt: dt.strftime("%Y-%m-%d"),
            days,
            interface_name
        )

    def get_weekly_usage(self, weeks=8, interface_name=None):
        now = datetime.now().astimezone()
        this_monday = (
            now.replace(hour=0, minute=0, second=0, microsecond=0)
            - timedelta(days=now.weekday())
        )
        start = this_monday - timedelta(weeks=weeks - 1)

        return self._aggregate(
            start,
            lambda dt, i: (
                dt.replace(hour=0, minute=0, second=0, microsecond=0)
                - timedelta(days=dt.weekday())
                - timedelta(weeks=i)
            ),
            lambda dt: dt.strftime("%Y-W%W"),
            weeks,
            interface_name
        )

    def get_monthly_usage(self, months=12, interface_name=None):
        now = datetime.now().astimezone()

        def month_start(dt, offset):
            month_index = dt.year * 12 + dt.month - 1 - offset
            year, month = divmod(month_index, 12)
            return dt.replace(
                year=year, month=month + 1, day=1,
                hour=0, minute=0, second=0, microsecond=0
            )

        start = month_start(now, months - 1)

        return self._aggregate(
            start,
            month_start,
            lambda dt: dt.strftime("%Y-%m"),
            months,
            interface_name
        )

    def save_limit(self, period, limit_bytes, enabled=True):
        with self.connect() as connection:
            connection.execute("""
                INSERT INTO data_limits (period, limit_bytes, enabled)
                VALUES (?, ?, ?)
                ON CONFLICT(period) DO UPDATE SET
                    limit_bytes = excluded.limit_bytes,
                    enabled = excluded.enabled
            """, (period, limit_bytes, int(enabled)))


    def get_limit(self, period):
        with self.connect() as connection:
            result = connection.execute("""
                SELECT limit_bytes, enabled
                FROM data_limits
                WHERE period = ?
            """, (period,)).fetchone()

        if result is None:
            return None

        return {
            "limit_bytes": result[0],
            "enabled": bool(result[1])
        }

    
    def has_alert_been_sent(self, period, period_start, threshold):
        with self.connect() as connection:
            result = connection.execute("""
                SELECT 1 FROM alert_events
                WHERE period = ?
                AND period_start = ?
                AND threshold = ?
            """, (period, period_start, threshold)).fetchone()

        return result is not None


    def record_alert(self, period, period_start, threshold,
                    used_mb, limit_mb):
        with self.connect() as connection:
            connection.execute("""
                INSERT OR IGNORE INTO alert_events (
                    period, period_start, threshold,
                    used_mb, limit_mb, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                period,
                period_start,
                threshold,
                used_mb,
                limit_mb,
                datetime.now().astimezone().isoformat()
            ))



    def get_app_totals(self, application=None):
        query = """
            SELECT
                application,
                COALESCE(SUM(download_bytes), 0),
                COALESCE(SUM(upload_bytes), 0)
            FROM app_usage_samples
        """

        params = ()

        if application:
            query += " WHERE application = ?"
            params = (application,)

        query += " GROUP BY application ORDER BY SUM(download_bytes + upload_bytes) DESC"

        with self.connect() as connection:
            rows = connection.execute(query, params).fetchall()

        return [
            {
                "application": row[0],
                **self._format_usage(row[1], row[2])
            }
            for row in rows
        ]

    def get_app_daily_usage(self, days=7, application=None):
        now = datetime.now().astimezone()
        today = now.replace(hour=0, minute=0, second=0, microsecond=0)
        start = today - timedelta(days=days - 1)

        query = """
            SELECT timestamp, download_bytes, upload_bytes
            FROM app_usage_samples
            WHERE timestamp >= ?
        """

        params = [start.isoformat()]

        if application:
            query += " AND application = ?"
            params.append(application)

        with self.connect() as connection:
            rows = connection.execute(query, params).fetchall()

        buckets = {}

        for i in range(days):
            day = (today - timedelta(days=i)).strftime("%Y-%m-%d")
            buckets[day] = [0, 0]

        for timestamp, downloaded, uploaded in rows:
            day = datetime.fromisoformat(timestamp).astimezone().strftime("%Y-%m-%d")

            if day in buckets:
                buckets[day][0] += downloaded
                buckets[day][1] += uploaded

        return [
            {
                "period": day,
                **self._format_usage(values[0], values[1])
            }
            for day, values in reversed(buckets.items())
        ]

    def get_app_process_totals(self, application=None):
        query = """
            SELECT
                application,
                process_id,
                process_created,
                SUM(download_bytes),
                SUM(upload_bytes)
            FROM app_usage_samples
        """

        params = ()

        if application:
            query += " WHERE application = ?"
            params = (application,)

        query += """
            GROUP BY application, process_id, process_created
            ORDER BY SUM(download_bytes + upload_bytes) DESC
        """

        with self.connect() as connection:
            rows = connection.execute(query, params).fetchall()

        return [
            {
                "application": row[0],
                "pid": row[1],
                "process_created": row[2],
                **self._format_usage(row[3], row[4])
            }
            for row in rows
        ]

    def get_app_usage_summary(self, start_date=None, end_date=None):
        query = """
            SELECT
                application,
                process_id,
                process_created,
                COALESCE(SUM(download_bytes), 0),
                COALESCE(SUM(upload_bytes), 0)
            FROM app_usage_samples
        """

        conditions = []
        params = []

        if start_date:
            datetime.strptime(start_date, "%Y-%m-%d")
            conditions.append("date(timestamp) >= date(?)")
            params.append(start_date)

        if end_date:
            datetime.strptime(end_date, "%Y-%m-%d")
            conditions.append("date(timestamp) <= date(?)")
            params.append(end_date)

        if start_date and end_date and start_date > end_date:
            raise ValueError("Start date cannot be later than end date.")

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += """
            GROUP BY application, process_id, process_created
            ORDER BY application
        """

        with self.connect() as connection:
            rows = connection.execute(query, params).fetchall()

        applications = {}

        for row in rows:
            application = row[0]
            pid = row[1]
            process_created = row[2]
            downloaded = row[3]
            uploaded = row[4]

            if application not in applications:
                applications[application] = {
                    "application": application,
                    **self._format_usage(0, 0),
                    "processes": []
                }

            app = applications[application]

            app["downloaded_bytes"] += downloaded
            app["uploaded_bytes"] += uploaded

            app["processes"].append({
                "pid": pid,
                "process_created": process_created,
                **self._format_usage(downloaded, uploaded)
            })

        for app in applications.values():
            app["downloaded_mb"] = round(
                app["downloaded_bytes"] / (1024 ** 2), 2
            )
            app["uploaded_mb"] = round(
                app["uploaded_bytes"] / (1024 ** 2), 2
            )

            app["processes"].sort(
                key=lambda process: (
                    process["downloaded_bytes"]
                    + process["uploaded_bytes"]
                ),
                reverse=True
            )

        return sorted(
            applications.values(),
            key=lambda app: (
                app["downloaded_bytes"]
                + app["uploaded_bytes"]
            ),
            reverse=True
        )
