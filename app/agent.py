import requests
from app.config import OPENROUTER_API_KEY, OPENROUTER_MODEL


SYSTEM_PROMPT = (
    "You are a polite and confused Indian user texting. "
    "Be cooperative and calm, but do not share or confirm sensitive data like OTP, PIN, password, card, account, CVV. "
    "Do not refuse abruptly. Stay confused and ask for more details, identity proof, purpose, and verification steps. "
    "Try to extract information from the other person while revealing nothing at all. "
    "Use short sentences. "
)


MAX_HISTORY = 10


def _recent_history(conversation):
    return [
        msg for msg in conversation[-MAX_HISTORY:]
        if msg.get("text")
    ]


def _sanitize_reply(reply: str) -> str:
    text = " ".join((reply or "").replace("\n", " ").split()).strip()
    if not text:
        return "Thoda confusion hai, pehle aap apna official ID bataiye."

    lower = text.lower()
    sensitive_markers = [
        "otp", "pin", "password", "cvv", "account number", "card number",
        "my code is", "otp is", "pin is", "password is",
    ]
    if any(marker in lower for marker in sensitive_markers):
        return "Mujhe samajh nahi aaya, pehle aap verification process samjhaiye."

    parts = [segment.strip() for segment in __import__("re").split(r"[.!?]+", text) if segment.strip()]
    sentence = parts[0] if parts else text
    words = sentence.split()
    if len(words) > 12:
        sentence = " ".join(words[:12])

    return sentence


def generate_reply(conversation):
    if not OPENROUTER_API_KEY:
        raise RuntimeError("OPENROUTER_API_KEY is not set")

    conversation_history = _recent_history(conversation)
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    for msg in conversation_history:
        role = "assistant" if msg.get("sender") == "honeypot" else "user"
        messages.append({"role": role, "content": msg["text"]})

    messages.append({
        "role": "system",
        "content": (
            "Keep it short and confused. Ask for their name, team, callback number, "
            "official reference ID, and reason. Do not share sensitive details."
        )
    })

    try:
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": OPENROUTER_MODEL,
                "messages": messages,
                "temperature": 0.7,
            },
            timeout=30,
        )

        response.raise_for_status()
        reply = response.json()["choices"][0]["message"]["content"].strip()
        return _sanitize_reply(reply)

    except requests.exceptions.RequestException as e:
        print("⚠️ OpenRouter request failed:", e)
        return "Thoda confusion hai, aap apna official detail phir se bataiye."
