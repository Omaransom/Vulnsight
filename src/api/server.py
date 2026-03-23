from collections import Counter
from datetime import datetime, timezone
from typing import List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from src.api.schemas import AlertPayload, ReportPayload
from src.core.settings import settings
from src.db.repository import AlertRepository

app = FastAPI(title="VulnSight Reporting API", version="1.0.0")
repository = AlertRepository(db_path=settings.database_path)


class ConnectionManager:
    def __init__(self):
        self._connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self._connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self._connections:
            self._connections.remove(websocket)

    async def broadcast_json(self, payload: dict):
        if not self._connections:
            return

        stale_connections = []
        for websocket in self._connections:
            try:
                await websocket.send_json(payload)
            except Exception:
                stale_connections.append(websocket)

        for websocket in stale_connections:
            self.disconnect(websocket)


ws_manager = ConnectionManager()


@app.get("/api/v1/health")
def health():
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc),
        "database_path": settings.database_path,
    }


@app.post("/api/v1/alerts")
async def ingest_alert(alert: AlertPayload):
    repository.save_alert(alert)
    payload = alert.model_dump() if hasattr(alert, "model_dump") else alert.dict()
    await ws_manager.broadcast_json(payload)
    return {"stored": True}


@app.get("/api/v1/alerts", response_model=List[AlertPayload])
def get_alerts(limit: int = 100):
    if limit <= 0:
        return []
    return repository.get_recent_alerts(limit=limit)


@app.post("/api/v1/reports/generate", response_model=ReportPayload)
def generate_report():
    alerts = repository.get_recent_alerts(limit=5000)
    total = len(alerts)
    malicious = sum(1 for a in alerts if a.is_malicious)
    benign = total - malicious
    ratio = (malicious / total) if total else 0.0

    dst_counter = Counter(a.destination_ip for a in alerts if a.destination_ip)
    top_targets = dict(dst_counter.most_common(5))
    severity_counter = Counter(a.severity for a in alerts if a.severity)

    return ReportPayload(
        generated_at=datetime.now(timezone.utc),
        total_events=total,
        malicious_events=malicious,
        benign_events=benign,
        malicious_ratio=ratio,
        severity_breakdown=dict(severity_counter),
        top_targets=top_targets,
    )


@app.websocket("/api/v1/ws/alerts")
async def alerts_ws(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
