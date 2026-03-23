import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    api_host: str = os.getenv("VULNSIGHT_API_HOST", "0.0.0.0")
    api_port: int = int(os.getenv("VULNSIGHT_API_PORT", "8000"))
    api_base_url: str = os.getenv("VULNSIGHT_API_BASE_URL", "http://127.0.0.1:8000")
    database_path: str = os.getenv("VULNSIGHT_DB_PATH", "database/vulnsight.db")
    ws_alerts_path: str = os.getenv("VULNSIGHT_WS_ALERTS_PATH", "/api/v1/ws/alerts")


settings = Settings()
