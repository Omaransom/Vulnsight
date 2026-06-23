"""
Single source of truth for turning a (prediction, confidence, attack_type)
triple into the UI-facing classification fields:
``confidence_level``, ``severity`` and ``triage_action``.

Why this module exists
----------------------
Three separate copies of this logic used to live in
``detection/manager.py``, ``api/server.py`` (PCAP worker) and
``api/client.py`` — each with DIFFERENT thresholds.  The same flow could be
labelled "high" by live detection and "medium" by a PCAP upload, and every
signature hit (confidence = 1.0) collapsed to "critical" regardless of what
the attack actually was.  All three paths now call :func:`classify_alert`.

Design
------
``severity`` is driven by **what the attack is** (a DDoS is inherently more
severe than a port scan), independent of detector confidence.  ``confidence``
only controls ``confidence_level`` and ``triage_action``.  Keeping the two
axes orthogonal means a signature-detected port scan is "medium" (recon) — not
"critical" — while its confidence_level can still be "very_high".
"""
import json
from pathlib import Path
from typing import Dict, Optional

# Base severity per attack type — what the detection MEANS, independent of how
# confident the detector is.  Reconnaissance (port scan) is the only non-"high"
# malicious bucket; everything representing an active attack notifies by default.
_ATTACK_BASE_SEVERITY: Dict[str, str] = {
    "ddos":              "critical",
    "data_exfiltration": "critical",
    "c2_beacon":         "high",
    "intrusion":         "high",
    "brute_force":       "high",
    "port_scan":         "medium",
    "normal":            "info",
}

_DEFAULT_MALICIOUS_SEVERITY = "high"

# Recommended triage action per severity — what to DO depends on how bad the
# detection is (severity), not how confident the detector is.
_SEVERITY_TRIAGE: Dict[str, str] = {
    "critical": "isolate_host_immediately",
    "high":     "investigate_now",
    "medium":   "review_packet_context",
    "low":      "monitor_and_revalidate",
}


def _load_threshold() -> float:
    """Load the trained decision threshold from model/threshold.json (fallback 0.5)."""
    try:
        path = Path(__file__).resolve().parents[2] / "model" / "threshold.json"
        t = float(json.loads(path.read_text())["threshold"])
        if 0.0 < t < 1.0:
            return t
    except Exception:
        pass
    return 0.5


# Loaded once at import — same value the inference engine applies.
TRAINED_THRESHOLD = _load_threshold()


def classify_alert(
    prediction: int,
    confidence: float,
    attack_type: Optional[str] = None,
) -> Dict[str, str]:
    """Map a single detection into UI-facing classification fields.

    Parameters
    ----------
    prediction : int
        1 = malicious, 0 = benign.
    confidence : float
        Probability of the predicted class (malicious prob for malicious
        predictions, benign prob for benign ones).
    attack_type : str, optional
        The classified attack category — drives malicious severity.

    Returns
    -------
    dict with keys ``confidence_level``, ``severity`` and ``triage_action``.
    """
    if prediction != 1:
        # Benign — ``confidence`` is the benign probability.
        level = (
            "very_high" if confidence >= 0.95
            else "high" if confidence >= 0.85
            else "medium" if confidence >= 0.70
            else "low"
        )
        return {
            "confidence_level": level,
            "severity": "info",
            "triage_action": "no_action_required",
        }

    severity = _ATTACK_BASE_SEVERITY.get(
        (attack_type or "intrusion").lower(), _DEFAULT_MALICIOUS_SEVERITY
    )

    # confidence_level reflects detector certainty (independent of severity).
    midpoint = (TRAINED_THRESHOLD + 1.0) / 2.0
    if confidence >= 0.95:
        level = "very_high"
    elif confidence >= midpoint:
        level = "high"
    elif confidence >= TRAINED_THRESHOLD:
        level = "medium"
    else:
        # Below the trained threshold — only reached defensively, since a
        # malicious prediction implies confidence >= threshold.
        level = "low"

    return {
        "confidence_level": level,
        "severity": severity,
        "triage_action": _SEVERITY_TRIAGE.get(severity, "investigate_now"),
    }
