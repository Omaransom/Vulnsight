import json
import sqlite3
import threading
from pathlib import Path
from typing import Dict, List

from src.api.schemas import AlertPayload
from src.db.schema import ensure_schema, table_exists


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
            ensure_schema(conn)
            conn.commit()

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
                if not table_exists(conn, "network_session"):
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
                if table_exists(conn, table):
                    counts[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        return counts
