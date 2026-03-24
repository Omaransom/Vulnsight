import json
import sqlite3
import threading
from pathlib import Path
from typing import Dict, List

from src.api.schemas import AlertPayload


class AlertRepository:
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    is_malicious INTEGER NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_dst_ip ON alerts(destination_ip)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS imported_sessions (
                    session_id TEXT PRIMARY KEY,
                    alert_id INTEGER
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS imported_legacy_alerts (
                    legacy_alert_id TEXT PRIMARY KEY,
                    alert_id INTEGER
                )
                """
            )
            self._ensure_teammate_tables(conn)
            self._migrate_legacy_alert_table(conn)
            conn.commit()

    def _table_exists(self, conn, table_name: str) -> bool:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = ? AND name = ? LIMIT 1",
            ("table", table_name),
        ).fetchone()
        return row is not None

    def _column_exists(self, conn, table_name: str, column_name: str) -> bool:
        rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        return any(r["name"] == column_name for r in rows)

    def _ensure_column(self, conn, table_name: str, column_name: str, column_ddl: str):
        if not self._column_exists(conn, table_name, column_name):
            conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_ddl}")

    def _ensure_teammate_tables(self, conn):
        """
        Keep teammate schema compatible with the app by creating/fixing optional tables.
        """
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pcap_file (
                id TEXT PRIMARY KEY,
                filename TEXT,
                filepath TEXT,
                file_size INTEGER,
                uploaded_at TEXT,
                source TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS packet (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                packet_length INTEGER,
                tcp_flags TEXT,
                pcap_id TEXT,
                session_id TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS network_session (
                id TEXT PRIMARY KEY,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                start_time TEXT,
                end_time TEXT,
                pcap_id TEXT,
                total_packets INTEGER,
                total_bytes INTEGER,
                duration REAL,
                packet_per_sec REAL,
                bytes_per_sec REAL,
                avg_packet_size REAL
            )
            """
        )
        self._ensure_column(conn, "network_session", "start_time", "start_time TEXT")
        self._ensure_column(conn, "network_session", "src_ip", "src_ip TEXT")
        self._ensure_column(conn, "network_session", "dst_ip", "dst_ip TEXT")
        self._ensure_column(conn, "network_session", "protocol", "protocol TEXT")
        self._ensure_column(conn, "network_session", "total_packets", "total_packets INTEGER")
        self._ensure_column(conn, "network_session", "total_bytes", "total_bytes INTEGER")
        self._ensure_column(conn, "network_session", "packet_per_sec", "packet_per_sec REAL")
        self._ensure_column(conn, "network_session", "bytes_per_sec", "bytes_per_sec REAL")
        self._ensure_column(conn, "network_session", "avg_packet_size", "avg_packet_size REAL")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_ns_start_time ON network_session(start_time)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_packet_session_id ON packet(session_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_packet_pcap_id ON packet(pcap_id)")

    def _migrate_legacy_alert_table(self, conn):
        """
        Migrate old teammate 'alert' table rows into canonical 'alerts' table once.
        """
        if not self._table_exists(conn, "alert"):
            return
        legacy_rows = conn.execute(
            """
            SELECT id, timestamp, severity, label, confidence, description, session_id
            FROM alert
            """
        ).fetchall()
        for row in legacy_rows:
            legacy_id = str(row["id"])
            already = conn.execute(
                "SELECT 1 FROM imported_legacy_alerts WHERE legacy_alert_id = ? LIMIT 1",
                (legacy_id,),
            ).fetchone()
            if already:
                continue
            payload = {
                "timestamp": row["timestamp"] or "1970-01-01T00:00:00Z",
                "source_ip": "0.0.0.0",
                "destination_ip": "0.0.0.0",
                "protocol": None,
                "interface": "legacy_alert_migration",
                "prediction": 1,
                "label": row["label"] or "LEGACY ALERT",
                "confidence": float(row["confidence"] or 0.5),
                "confidence_level": "high" if float(row["confidence"] or 0.0) >= 0.8 else "medium",
                "severity": str(row["severity"] or "medium"),
                "triage_action": row["description"] or "review_legacy_alert",
                "is_malicious": True,
                "shap_top_features": [],
                "legacy_context": {"session_id": row["session_id"], "legacy_alert_id": legacy_id},
            }
            cursor = conn.execute(
                """
                INSERT INTO alerts (
                    timestamp, source_ip, destination_ip, severity, is_malicious, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["timestamp"],
                    payload["source_ip"],
                    payload["destination_ip"],
                    payload["severity"],
                    1,
                    json.dumps(payload),
                ),
            )
            conn.execute(
                "INSERT OR REPLACE INTO imported_legacy_alerts (legacy_alert_id, alert_id) VALUES (?, ?)",
                (legacy_id, cursor.lastrowid),
            )

    @staticmethod
    def _to_payload_dict(alert: AlertPayload) -> Dict:
        if hasattr(alert, "model_dump"):
            return alert.model_dump()
        return alert.dict()

    def save_alert(self, alert: AlertPayload):
        payload = self._to_payload_dict(alert)
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO alerts (
                        timestamp, source_ip, destination_ip, severity, is_malicious, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload["timestamp"],
                        payload["source_ip"],
                        payload["destination_ip"],
                        payload["severity"],
                        1 if payload["is_malicious"] else 0,
                        json.dumps(payload),
                    ),
                )
                conn.commit()

    def get_recent_alerts(self, limit: int = 100) -> List[AlertPayload]:
        query_limit = max(1, min(limit, 5000))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT payload_json
                FROM alerts
                ORDER BY id DESC
                LIMIT ?
                """,
                (query_limit,),
            ).fetchall()

        payloads = [json.loads(r["payload_json"]) for r in rows]
        payloads.reverse()
        return [AlertPayload(**payload) for payload in payloads]

    def import_network_sessions_as_alerts(self, limit: int = 1000) -> int:
        """
        Import teammate DB sessions (network_session) into canonical alerts table.
        Safe to run repeatedly; already imported sessions are skipped.
        """
        query_limit = max(1, min(limit, 10_000))
        imported = 0
        with self._lock:
            with self._connect() as conn:
                if not self._table_exists(conn, "network_session"):
                    return 0
                rows = conn.execute(
                    """
                    SELECT ns.id, ns.start_time, ns.src_ip, ns.dst_ip, ns.protocol,
                           ns.packet_per_sec, ns.bytes_per_sec, ns.total_packets, ns.total_bytes
                    FROM network_session ns
                    LEFT JOIN imported_sessions imp ON imp.session_id = ns.id
                    WHERE imp.session_id IS NULL
                    ORDER BY ns.start_time DESC
                    LIMIT ?
                    """,
                    (query_limit,),
                ).fetchall()

                for row in rows:
                    packets_per_sec = float(row["packet_per_sec"] or 0.0)
                    bytes_per_sec = float(row["bytes_per_sec"] or 0.0)
                    total_packets = int(row["total_packets"] or 0)
                    total_bytes = int(row["total_bytes"] or 0)
                    is_malicious = packets_per_sec > 400 or bytes_per_sec > 500_000
                    severity = "high" if is_malicious else "info"
                    confidence = min(0.99, 0.55 + (packets_per_sec / 2000.0))
                    payload = {
                        "timestamp": row["start_time"] or "1970-01-01T00:00:00Z",
                        "source_ip": row["src_ip"] or "0.0.0.0",
                        "destination_ip": row["dst_ip"] or "0.0.0.0",
                        "protocol": None,
                        "interface": "network_session_import",
                        "prediction": 1 if is_malicious else 0,
                        "label": "ATTACK DETECTED" if is_malicious else "NORMAL",
                        "confidence": float(confidence),
                        "confidence_level": "high" if confidence >= 0.8 else "medium",
                        "severity": severity,
                        "triage_action": (
                            "investigate_session_now"
                            if is_malicious
                            else "monitor_traffic_pattern"
                        ),
                        "is_malicious": bool(is_malicious),
                        "shap_top_features": [],
                        "session_context": {
                            "session_id": row["id"],
                            "packet_per_sec": packets_per_sec,
                            "bytes_per_sec": bytes_per_sec,
                            "total_packets": total_packets,
                            "total_bytes": total_bytes,
                        },
                    }
                    cursor = conn.execute(
                        """
                        INSERT INTO alerts (
                            timestamp, source_ip, destination_ip, severity, is_malicious, payload_json
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            payload["timestamp"],
                            payload["source_ip"],
                            payload["destination_ip"],
                            payload["severity"],
                            1 if payload["is_malicious"] else 0,
                            json.dumps(payload),
                        ),
                    )
                    conn.execute(
                        "INSERT OR REPLACE INTO imported_sessions (session_id, alert_id) VALUES (?, ?)",
                        (row["id"], cursor.lastrowid),
                    )
                    imported += 1
                conn.commit()
        return imported

    def db_counts(self) -> Dict[str, int]:
        with self._connect() as conn:
            counts = {
                "alerts": conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
                "network_session": 0,
                "packet": 0,
                "pcap_file": 0,
            }
            for table in ("network_session", "packet", "pcap_file"):
                if self._table_exists(conn, table):
                    counts[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        return counts
