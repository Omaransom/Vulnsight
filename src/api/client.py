from datetime import datetime, timezone
from typing import Any, Dict, List

import requests


class DashboardReporter:
    def __init__(self, base_url: str = "http://127.0.0.1:8000", timeout: int = 3):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    @staticmethod
    def _classify_confidence(prediction: int, confidence: float) -> Dict[str, str]:
        if prediction == 1:
            if confidence >= 0.95:
                return {
                    "confidence_level": "very_high",
                    "severity": "critical",
                    "triage_action": "isolate_host_immediately",
                }
            if confidence >= 0.80:
                return {
                    "confidence_level": "high",
                    "severity": "high",
                    "triage_action": "investigate_now",
                }
            if confidence >= 0.60:
                return {
                    "confidence_level": "medium",
                    "severity": "medium",
                    "triage_action": "review_packet_context",
                }
            return {
                "confidence_level": "low",
                "severity": "low",
                "triage_action": "monitor_and_revalidate",
            }

        if confidence >= 0.80:
            return {
                "confidence_level": "high",
                "severity": "info",
                "triage_action": "no_action_needed",
            }
        if confidence >= 0.60:
            return {
                "confidence_level": "medium",
                "severity": "info",
                "triage_action": "observe_traffic_pattern",
            }
        return {
            "confidence_level": "low",
            "severity": "warning",
            "triage_action": "mark_as_uncertain_benign",
        }

    def post_alert(
        self,
        metadata: Dict[str, Any],
        prediction: int,
        confidence: float,
        shap_top_features: List[Dict[str, Any]],
    ) -> bool:
        is_malicious = prediction == 1
        classification = self._classify_confidence(prediction=prediction, confidence=confidence)
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
            "shap_top_features": shap_top_features,
        }

        try:
            response = requests.post(
                f"{self.base_url}/api/v1/alerts",
                json=payload,
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
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException:
            return {}
