
import logging
import requests
from app.config import GUVI_CALLBACK_URL

logger = logging.getLogger(__name__)


def _coerce_list(value):
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _build_extracted_intelligence(intelligence: dict) -> dict:
    intelligence = intelligence or {}
    return {
        "phoneNumbers": _coerce_list(intelligence.get("phoneNumbers")),
        "bankAccounts": _coerce_list(intelligence.get("bankAccounts")),
        "upiIds": _coerce_list(intelligence.get("upiIds")),
        "phishingLinks": _coerce_list(intelligence.get("phishingLinks")),
        "emailAddresses": _coerce_list(intelligence.get("emailAddresses")),
    }


def _compute_engagement_duration_seconds(messages) -> int:
    if not isinstance(messages, list) or not messages:
        return 0

    timestamps = []
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        ts = msg.get("timestamp")
        if ts is None:
            continue
        try:
            ts_int = int(ts)
        except (TypeError, ValueError):
            continue
        timestamps.append(ts_int)

    if len(timestamps) < 2:
        return 0

    start = min(timestamps)
    end = max(timestamps)
    delta = max(0, end - start)

    # Heuristic: timestamps above 1e12 are likely epoch milliseconds.
    if start > 1_000_000_000_000 or end > 1_000_000_000_000:
        return delta // 1000
    return delta

def send_final_callback(session_id, session_data):
    intelligence = session_data.get("intelligence") or {}
    suspicious_keywords = intelligence.get("suspiciousKeywords") or []

    scam_scenarios = intelligence.get("scamScenarios") or {}
    scenario_note = ""
    if isinstance(scam_scenarios, dict) and scam_scenarios:
        parts = []
        for scenario, matches in scam_scenarios.items():
            if not matches:
                continue
            parts.append(f"{scenario} ({', '.join(map(str, matches))})")
        if parts:
            scenario_note = "Detected scenarios: " + "; ".join(parts)

    agent_notes = "Potential scam pattern detected; asked for verification details."
    if scenario_note and suspicious_keywords:
        agent_notes = f"{scenario_note}. Suspicious keywords observed: {', '.join(map(str, suspicious_keywords))}"
    elif scenario_note:
        agent_notes = scenario_note
    elif suspicious_keywords:
        agent_notes = f"Suspicious keywords observed: {', '.join(map(str, suspicious_keywords))}"

    payload = {
        "sessionId": session_id,
        "scamDetected": bool(session_data.get("scamDetected", False)),
        "totalMessagesExchanged": len(session_data.get("messages", [])),
        "engagementDurationSeconds": _compute_engagement_duration_seconds(session_data.get("messages", [])),
        "extractedIntelligence": _build_extracted_intelligence(intelligence),
        "agentNotes": agent_notes
    }
    try:
        requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
    except requests.RequestException:
        logger.exception("Failed to send final callback")
