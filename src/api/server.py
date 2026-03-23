from collections import Counter, deque
from datetime import datetime, timezone
from typing import List

from fastapi import FastAPI

from src.api.schemas import AlertPayload, ReportPayload

app = FastAPI(title="VulnSight Reporting API", version="1.0.0")

ALERT_BUFFER = deque(maxlen=5000)


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc)}


@app.post("/api/v1/alerts")
def ingest_alert(alert: AlertPayload):
    ALERT_BUFFER.append(alert)
    return {"stored": True, "buffer_size": len(ALERT_BUFFER)}


@app.get("/api/v1/alerts", response_model=List[AlertPayload])
def get_alerts(limit: int = 100):
    if limit <= 0:
        return []
    return list(ALERT_BUFFER)[-limit:]


@app.post("/api/v1/reports/generate", response_model=ReportPayload)
def generate_report():
    alerts = list(ALERT_BUFFER)
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
