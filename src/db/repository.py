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
