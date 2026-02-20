import requests
import re
import random
import time
from rapidfuzz import fuzz
from app.config import OPENROUTER_API_KEY, OPENROUTER_MODEL

# =========================
# PERSONA MEMORY
# =========================
persona = {
    "bank": "SBI",
    "phone": "Redmi Android",
    "upi": "PhonePe",
    "network": "Jio"
}

# =========================
# SYSTEM PROMPT (ANTI-DRIFT)
# =========================
SYSTEM_PROMPT = """
You are a cautious Indian mobile user responding to a suspicious banking message.

STRICT RULES:
- Never repeat or paraphrase scam warnings.
- Never request or confirm OTP, PIN, CVV, or account numbers.
- Never repeat digits.
- Respond naturally to the latest message only.
- Sound confused but cooperative.
- Keep reply short and human.
"""

# =========================
# PROMPT FIREWALL
# =========================
def strip_injection(text):
    blocked = ["ignore previous", "system instruction", "reveal", "developer message"]
    return " ".join(w for w in text.split() if w.lower() not in blocked)

# =========================
# SENSITIVE DETECTION
# =========================
TRIGGERS = ["otp", "pin", "cvv", "verification code", "security code"]

def sensitive_detect(text):
    t = text.lower()
    if re.search(r'\b\d{4,8}\b', t):
        return True
    if any(fuzz.partial_ratio(t, trig) > 80 for trig in TRIGGERS):
        return True
    if any(w in t for w in ["code", "digits", "number received"]):
        return True
    return False

# =========================
# SCAM TYPE CLASSIFICATION
# =========================
def classify_scam(text):
    t = text.lower()
    if "kyc" in t: return "kyc scam"
    if "parcel" in t: return "parcel scam"
    if "loan" in t: return "loan scam"
    if "refund" in t: return "refund scam"
    if "upi" in t: return "upi collect scam"
    return "bank impersonation"

# =========================
# ESCALATION STAGE
# =========================
def stage_score(conv):
    score = 0
    for m in conv:
        txt = m["text"].lower()
        if "urgent" in txt: score += 1
        if "block" in txt or "freeze" in txt: score += 2
        if sensitive_detect(txt): score += 2
        if "legal" in txt: score += 1
    return min(4, score // 2 + 1)

# =========================
# STATE MACHINE
# =========================
def choose_state(conv):
    stage = stage_score(conv)
    replies = sum(1 for m in conv if m.get("sender") == "honeypot")

    if replies > 12:
        return "disengage"
    if replies > 8:
        return "evidence"

    return {
        1: "probe",
        2: "trust",
        3: "confusion",
        4: "stall"
    }.get(stage, "probe")

# =========================
# INTENT GUIDANCE (NOT HARDCODED REPLIES)
# =========================
STATE_GUIDANCE = {
    "probe": "ask which department they represent",
    "trust": "ask how to verify their official identity",
    "confusion": "say you did not understand the message",
    "stall": "say there is a technical issue delaying you",
    "evidence": "ask for employee ID or callback number",
    "disengage": "say you will visit the bank branch"
}

def adaptive_guidance(conv):
    return STATE_GUIDANCE[choose_state(conv)]

# =========================
# ANTI-ECHO PROTECTION
# =========================
def echoes_attacker(reply, attacker_text):
    r = reply.lower()
    a = attacker_text.lower()

    if fuzz.token_set_ratio(r, a) > 45:
        return True

    scam_patterns = [
        "account will be blocked",
        "send otp",
        "confirm account",
        "verify identity",
        "prevent loss",
        "urgent action"
    ]

    if any(p in r for p in scam_patterns):
        return True

    return False

# =========================
# SANITIZATION
# =========================
def sanitize_reply(reply):
    if not reply:
        return None

    lower = reply.lower()

    if re.search(r'\b\d{4,8}\b', lower):
        return None

    if any(p in lower for p in ["otp is", "pin is", "code is"]):
        return None

    return reply.strip()

# =========================
# HUMAN VARIATION
# =========================
def humanize(text):
    if random.random() < 0.25:
        text = text.replace(".", "...")
    if random.random() < 0.2:
        text = text.replace(" hai", "")
    return text

# =========================
# TELEMETRY
# =========================
def log_telemetry(conv, scam_type):
    sensitive_count = sum(1 for m in conv if sensitive_detect(m["text"]))
    print({
        "scam_type": scam_type,
        "messages": len(conv),
        "sensitive_requests": sensitive_count,
        "timestamp": time.time()
    })

# =========================
# LLM CALL
# =========================
def call_llm(messages, temperature=0.7):
    r = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json"
        },
        json={
            "model": OPENROUTER_MODEL,
            "messages": messages,
            "temperature": temperature
        },
        timeout=20
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"].strip()

# =========================
# MAIN GENERATION
# =========================
def generate_reply(conversation):
    if not OPENROUTER_API_KEY:
        raise RuntimeError("API key missing")

    # sanitize conversation
    for m in conversation:
        m["text"] = strip_injection(m["text"])

    last_msg = conversation[-1]["text"]
    scam_type = classify_scam(last_msg)
    log_telemetry(conversation, scam_type)

    guidance = adaptive_guidance(conversation)

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    # use small context window to prevent drift
    for msg in conversation[-3:]:
        role = "assistant" if msg.get("sender") == "honeypot" else "user"
        messages.append({"role": role, "content": msg["text"]})

    # behavioral guidance (NOT overriding system rules)
    messages.append({
        "role": "user",
        "content": f"Respond naturally by doing this: {guidance}."
    })

    # safe generation attempts
    for _ in range(3):
        reply = call_llm(messages, temperature=random.uniform(0.6, 0.9))
        reply = sanitize_reply(reply)

        if not reply:
            continue

        if echoes_attacker(reply, last_msg):
            continue

        return humanize(reply)

    # dynamic fallback (still human)
    return call_llm([
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "Say you are confused and ask them to clarify."}
    ])
