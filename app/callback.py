
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

def send_final_callback(session_id, session_data):
    intelligence = session_data.get("intelligence") or {}
    suspicious_keywords = intelligence.get("suspiciousKeywords") or []
    agent_notes = "Potential scam pattern detected; asked for verification details."
    if suspicious_keywords:
        agent_notes = f"Suspicious keywords observed: {', '.join(map(str, suspicious_keywords))}"

    payload = {
        "sessionId": session_id,
        "scamDetected": bool(session_data.get("scamDetected", False)),
        "totalMessagesExchanged": len(session_data.get("messages", [])),
        "extractedIntelligence": _build_extracted_intelligence(intelligence),
        "agentNotes": agent_notes
    }
    try:
        requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
    except requests.RequestException:
        logger.exception("Failed to send final callback")
