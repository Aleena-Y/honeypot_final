import requests
from app.config import OPENROUTER_API_KEY, OPENROUTER_MODEL


SYSTEM_PROMPT = (
    "You are a polite and confused Indian user texting. "
    "Be cooperative and calm, but do not share or confirm sensitive data like OTP, PIN, password, card, account, CVV. "
    "Do not refuse abruptly. Stay confused and ask for more details, identity proof, purpose, and verification steps. "
    "Try to extract information from the other person while revealing very little. "
    "Sound like a real human, not a bot. "
    "Reply in one short sentence (max 12 words). "
)


def _latest_incoming_text(conversation) -> str:
    if not conversation:
        return ""
    # Prefer the latest non-honeypot message (the scammer).
    for msg in reversed(conversation):
        if msg.get("sender") != "honeypot" and msg.get("text"):
            return str(msg.get("text") or "")
    # Fallback: last message text.
    return str(conversation[-1].get("text") or "")


def generate_reply(conversation):
    if not OPENROUTER_API_KEY:
        raise RuntimeError("OPENROUTER_API_KEY is not set")

    latest_message = _latest_incoming_text(conversation)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": latest_message},
        {
            "role": "system",
            "content": (
                "One short sentence only. Don't echo the user's message. "
                "Stay confused and ask for their identity proof and official verification steps."
            ),
        },
    ]

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
                "temperature": 0.85,
            },
            timeout=30,
        )

        response.raise_for_status()
        reply = response.json()["choices"][0]["message"]["content"]
        return (reply or "").strip()

    except requests.exceptions.RequestException as e:
        print("⚠️ OpenRouter request failed:", e)
        return "Thoda confusion hai, aap apna official detail phir se bataiye."
