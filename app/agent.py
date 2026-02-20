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


def _next_step_from_history(conversation_history) -> str:
    user_text = " ".join(
        msg["text"].lower()
        for msg in conversation_history
        if msg.get("sender") != "honeypot"
    )

    last_honeypot = [
        msg["text"].strip().lower()
        for msg in conversation_history
        if msg.get("sender") == "honeypot" and msg.get("text")
    ]
    last_honeypot_text = last_honeypot[-1] if last_honeypot else ""

    probes = [
        ("name", ["name", "who are you"], "Aapka poora naam kya hai?"),
        ("team", ["team", "department", "bank", "office"], "Aap kis team se bol rahe ho?"),
        ("callback", ["callback", "call back", "number", "phone"], "Aapka callback number share karo please."),
        ("reference", ["reference", "ticket", "case id", "complaint"], "Official reference ID kya hai?"),
        ("reason", ["reason", "purpose", "why", "kisliye"], "Mujhe exact reason samjha do please."),
    ]

    pending = [
        prompt for _, keywords, prompt in probes
        if not any(keyword in user_text for keyword in keywords)
    ]

    options = pending + ["Verification process step by step samjha do please."]
    for option in options:
        if option.lower() != last_honeypot_text:
            return option

    return "Please details phir se clear karo, mujhe confusion hai."


def generate_reply(conversation):
    if not OPENROUTER_API_KEY:
        raise RuntimeError("OPENROUTER_API_KEY is not set")

    conversation_history = _recent_history(conversation)
    next_step = _next_step_from_history(conversation_history)
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    for msg in conversation_history:
        role = "assistant" if msg.get("sender") == "honeypot" else "user"
        messages.append({"role": role, "content": msg["text"]})

    messages.append({
        "role": "system",
        "content": (
            "Keep it short and confused. One short sentence only. "
            "Do not share sensitive details. "
            f"Proceed with this next question: {next_step}"
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
        sanitized = _sanitize_reply(reply)

        if sanitized.lower() == next_step.lower() and conversation_history:
            return next_step

        last_honeypot = next(
            (msg["text"].strip().lower() for msg in reversed(conversation_history)
             if msg.get("sender") == "honeypot" and msg.get("text")),
            ""
        )
        if sanitized.lower() == last_honeypot:
            return next_step

        return sanitized

    except requests.exceptions.RequestException as e:
        print("⚠️ OpenRouter request failed:", e)
        return "Thoda confusion hai, aap apna official detail phir se bataiye."
