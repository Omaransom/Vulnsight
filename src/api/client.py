from datetime import datetime, timezone
from typing import Any, Dict, List

import requests
from src.core.settings import settings
from src.core.severity import classify_alert


class DashboardReporter:
    def __init__(self, base_url: str = settings.api_base_url, timeout: int = 3):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._token = settings.api_auth_token.strip()

    def _login_for_token(self) -> str:
        username = settings.api_auth_username.strip()
        password = settings.api_auth_password
        if not username or not password:
            return ""
        try:
            response = requests.post(
                f"{self.base_url}/api/v1/auth/login",
                json={"username": username, "password": password},
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json()
            return payload.get("access_token", "")
        except requests.RequestException:
            return ""

    def _auth_headers(self) -> Dict[str, str]:
        if not self._token:
            self._token = self._login_for_token()
        if not self._token:
            return {}
        return {"Authorization": f"Bearer {self._token}"}

    def post_alert(
        self,
        metadata: Dict[str, Any],
        prediction: int,
        confidence: float,
        shap_top_features: List[Dict[str, Any]],
        attack_type: str | None = None,
    ) -> bool:
        is_malicious = prediction == 1
        classification = classify_alert(prediction, confidence, attack_type)
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": metadata.get("src_ip", ""),
            "destination_ip": metadata.get("dst_ip", ""),
            "protocol": metadata.get("protocol"),
            "interface": metadata.get("interface"),
            "prediction": prediction,
            "label": "ATTACK DETECTED" if is_malicious else "NORMAL",
            "confidence": confidence,
            "confidence_level": classification["confidence_level"],
            "severity": classification["severity"],
            "triage_action": classification["triage_action"],
            "is_malicious": is_malicious,
            "attack_type": attack_type,
            "shap_top_features": shap_top_features,
        }

        try:
            response = requests.post(
                f"{self.base_url}/api/v1/alerts",
                json=payload,
                headers=self._auth_headers(),
                timeout=self.timeout,
            )
            if response.status_code == 401:
                self._token = self._login_for_token()
                response = requests.post(
                    f"{self.base_url}/api/v1/alerts",
                    json=payload,
                    headers=self._auth_headers(),
                    timeout=self.timeout,
                )
            response.raise_for_status()
            return True
        except requests.RequestException:
            return False

    def generate_report(self) -> Dict[str, Any]:
        try:
            response = requests.post(
                f"{self.base_url}/api/v1/reports/generate",
                headers=self._auth_headers(),
                timeout=self.timeout,
            )
            if response.status_code == 401:
                self._token = self._login_for_token()
                response = requests.post(
                    f"{self.base_url}/api/v1/reports/generate",
                    headers=self._auth_headers(),
                    timeout=self.timeout,
                )
            response.raise_for_status()
            return response.json()
        except requests.RequestException:
            return {}
