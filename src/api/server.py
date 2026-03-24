from collections import Counter
from datetime import datetime, timezone
from typing import List
from fastapi import Depends, FastAPI, WebSocket, WebSocketDisconnect
from src.api.auth.dependencies import require_roles, set_auth_repository as set_auth_dep_repository
from src.api.auth.routes import router as auth_router
from src.api.auth.routes import set_auth_repository as set_auth_routes_repository
from src.api.schemas import AlertPayload, ReportPayload
from src.core.settings import settings
from src.db.auth_repository import AuthRepository
from src.db.repository import AlertRepository

app = FastAPI(title="VulnSight Reporting API", version="1.0.0")
repository = AlertRepository(db_path=settings.database_path)
auth_repository = AuthRepository(db_path=settings.database_path)
auth_repository.ensure_default_user(
    username=settings.auth_bootstrap_admin_username,
    password=settings.auth_bootstrap_admin_password,
    role="admin",
)
set_auth_dep_repository(auth_repository)
set_auth_routes_repository(auth_repository)
app.include_router(auth_router)


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
    counts = repository.db_counts()
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc),
        "database_path": settings.database_path,
        "counts": counts,
    }


@app.post("/api/v1/alerts")
async def ingest_alert(
    alert: AlertPayload,
    _=Depends(require_roles("admin", "sensor")),
):
    repository.save_alert(alert)
    payload = alert.model_dump() if hasattr(alert, "model_dump") else alert.dict()
    await ws_manager.broadcast_json(payload)
    return {"stored": True}


@app.get("/api/v1/alerts", response_model=List[AlertPayload])
def get_alerts(
    limit: int = 100,
    _=Depends(require_roles("admin", "analyst", "viewer")),
):
    if limit <= 0:
        return []
    return repository.get_recent_alerts(limit=limit)


@app.post("/api/v1/reports/generate", response_model=ReportPayload)
def generate_report(_=Depends(require_roles("admin", "analyst"))):
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


@app.post("/api/v1/admin/import-flows")
def import_flows(
    limit: int = 1000,
    _=Depends(require_roles("admin", "analyst")),
):
    imported = repository.import_flows_as_alerts(limit=limit)
    return {"imported": imported, "counts": repository.db_counts()}


@app.websocket("/api/v1/ws/alerts")
async def alerts_ws(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
