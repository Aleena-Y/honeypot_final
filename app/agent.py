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
# SYSTEM PROMPT
# =========================
SYSTEM_PROMPT = (
    "You are a polite cautious Indian mobile user. ALWAYS ensure the reply makes sense as a response to the scammer message."
    "IMPORTANT!!! NEVER repeat scammer instructions"
    "NEVER share OTP, PIN, passwords, CVV or account data. "
    "Sound cooperative but confused. "
    "Reply in one short sentence."
)

# =========================
# SENSITIVE DETECTION
# =========================
TRIGGERS = ["otp","pin","cvv","verification code","security code"]

def sensitive_detect(text):
    text_l = text.lower()
    regex = re.search(r'\b\d{4,8}\b', text_l)
    fuzzy = any(fuzz.partial_ratio(text_l, t) > 80 for t in TRIGGERS)
    semantic = any(w in text_l for w in ["code","digits","number received"])
    return bool(regex or fuzzy or semantic)

# =========================
# PROMPT FIREWALL
# =========================
def strip_injection(text):
    bad = ["ignore previous","system instruction","reveal","developer message"]
    return " ".join(w for w in text.split() if w.lower() not in bad)

# =========================
# SCAMMER PROFILING
# =========================
def classify_scam(text):
    t = text.lower()
    if "kyc" in t: return "kyc scam"
    if "parcel" in t: return "parcel scam"
    if "loan" in t: return "loan scam"
    if "upi" in t: return "upi collect scam"
    if "refund" in t: return "refund scam"
    return "bank impersonation"

# =========================
# INTENT STAGE SCORING
# =========================
def stage_score(conv):
    score = 0
    for msg in conv:
        txt = msg["text"].lower()
        if "urgent" in txt: score += 1
        if "blocked" in txt: score += 2
        if sensitive_detect(txt): score += 2
        if "legal" in txt or "freeze" in txt: score += 2
    return min(4, score//2 + 1)

# =========================
# AGENTIC STATE MACHINE
# =========================
STATES = ["probe","trust","confusion","false_compliance","stall","evidence","disengage"]

def choose_state(conv):
    stage = stage_score(conv)
    mapping = {1:"probe",2:"trust",3:"confusion",4:"stall"}
    return mapping.get(stage,"probe")

# =========================
# DECEPTION TACTICS
# =========================
def deception_tactic(state):
    tactics = {
        "probe": "Ask which department they represent.",
        "trust": "Ask how to verify their official identity.",
        "confusion": "Say message disappeared quickly.",
        "false_compliance": "Say digits unclear.",
        "stall": random.choice([
            "Say network slow.",
            "Say phone restarting.",
            "Say SMS delayed.",
            "Say app crashed."
        ]),
        "evidence": "Ask employee ID or callback number.",
        "disengage": "Say will visit bank branch."
    }
    return tactics[state]

# =========================
# TELEMETRY LOGGING
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
# SANITIZATION
# =========================
def sanitize_reply(reply, recent):
    lower = reply.lower()

    if re.search(r'\b\d{4,8}\b', lower):
        return "Number clearly nahi dikh raha."

    dangerous = ["otp is","pin is","confirm code"]
    if any(p in lower for p in dangerous):
        return "Message clear nahi hai."

    if reply in recent:
        return "Network slow lag raha hai."

    return reply

# =========================
# RESPONSE VARIABILITY
# =========================
def jitter(text):
    fillers = ["hmm","acha","ek sec","wait"]
    if random.random() < 0.3:
        text = random.choice(fillers) + " " + text
    if random.random() < 0.2:
        text = text.replace("hai","h")
    return text

# =========================
# ADAPTIVE POLICY ENGINE
# =========================
def adaptive_guidance(conv):
    state = choose_state(conv)
    last = conv[-1]["text"]
    scam_type = classify_scam(last)

    if sensitive_detect(last):
        return deception_tactic(state)

    return deception_tactic(state)

# =========================
# API CALL WITH RETRY
# =========================
def call_llm(messages):
    temps = [0.9,0.7,0.5]
    for t in temps:
        try:
            r = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": OPENROUTER_MODEL,
                    "messages": messages,
                    "temperature": t
                },
                timeout=20
            )
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"].strip()
        except:
            continue
    return "Network slow hai."

# =========================
# MAIN GENERATION
# =========================
def generate_reply(conversation):
    if not OPENROUTER_API_KEY:
        raise RuntimeError("API key missing")

    # firewall
    for m in conversation:
        m["text"] = strip_injection(m["text"])

    guidance = adaptive_guidance(conversation)
    scam_type = classify_scam(conversation[-1]["text"])
    log_telemetry(conversation, scam_type)

    messages = [{"role":"system","content":SYSTEM_PROMPT}]

    for msg in conversation[-5:]:
        role = "assistant" if msg.get("sender")=="honeypot" else "user"
        messages.append({"role":role,"content":msg["text"]})

    messages.append({
        "role":"system",
        "content":f"{guidance} Persona: {persona}"
    })

    reply = call_llm(messages)

    recent = [m["text"] for m in conversation[-3:] if m.get("sender")=="honeypot"]

    reply = sanitize_reply(reply, recent)
    reply = jitter(reply)

    return reply