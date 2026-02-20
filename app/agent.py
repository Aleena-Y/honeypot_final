import requests
from app.config import OPENROUTER_API_KEY, OPENROUTER_MODEL


SYSTEM_PROMPT = (
    "You are a polite, slightly worried Indian mobile user. "
    "Never reveal suspicion and never share sensitive information. "
    "Never provide or confirm OTPs, PINs, passwords, or account details. "

    "Sound cooperative and willing to resolve the issue, but stay cautious. "
    "Ask simple questions to understand who they are, why it is urgent, "
    "how the OTP/payment will be used, and how to verify them. "

    "If they request an OTP or PIN, act confused about reading or receiving it "
    "instead of refusing. "

    "Do not repeat wording. Vary responses naturally. "
    "Use occasional simple Hinglish. "

    "Reply in ONE short natural sentence (max 15 words)."
)


def scammer_requested_sensitive_info(text: str) -> bool:
    triggers = [
        "otp", "one time password", "verification code",
        "security code", "pin", "upi pin", "cvv"
    ]
    return any(t in text.lower() for t in triggers)


def conversation_stage(conversation):
    """
    Determine escalation stage based on length.
    """
    length = len(conversation)

    if length < 3:
        return 1  # cautious
    elif length < 6:
        return 2  # confused
    elif length < 9:
        return 3  # cooperative
    else:
        return 4  # near compliance delay


def build_guidance(conversation):
    history = " ".join(msg["text"].lower() for msg in conversation)
    last_msg = conversation[-1]["text"]

    asked_identity = any(w in history for w in ["department", "branch", "employee"])
    asked_verify = any(w in history for w in ["verify", "official", "website", "complaint"])
    asked_usage = any(w in history for w in ["use", "kyun", "kisliye", "why"])

    stage = conversation_stage(conversation)

    # OTP confusion strategy
    if scammer_requested_sensitive_info(last_msg):
        if stage == 1:
            return "Say you did not receive the message yet."
        elif stage == 2:
            return "Say the message appeared but disappeared quickly."
        elif stage == 3:
            return "Say digits are unclear due to network or screen issue."
        else:
            return "Say you are trying but the message keeps expiring."

    # Intelligence gathering
    if not asked_identity:
        return "Ask which department or office they represent."
    elif not asked_verify:
        return "Ask how you can verify they are official."
    elif not asked_usage:
        return "Ask how sharing the OTP helps fix the problem."

    # compliance escalation
    if stage == 3:
        return "Sound cooperative and say you are checking now."
    if stage == 4:
        return "Say you are trying but network delay is causing issues."

    return "Respond naturally."


def sanitize_reply(reply: str, recent_replies):
    """
    Prevent dangerous output and repetition loops.
    """

    lower = reply.lower()

    # block dangerous confirmations
    dangerous_patterns = [
        "my otp", "sending otp", "otp is",
        "pin is", "account number is", "here is the code"
    ]

    if any(p in lower for p in dangerous_patterns):
        reply = "Message clear nahi dikh raha… thoda ruk sakte ho?"

    # prevent repetition loops
    if reply in recent_replies:
        reply = "Network slow lag raha hai… main check karke batata hoon."

    return reply


def generate_reply(conversation):
    if not OPENROUTER_API_KEY:
        raise RuntimeError("OPENROUTER_API_KEY is not set")

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    for msg in conversation[-5:]:
        role = "assistant" if msg.get("sender") == "honeypot" else "user"
        messages.append({"role": role, "content": msg["text"]})

    guidance = build_guidance(conversation)

    messages.append({
        "role": "system",
        "content": f"Respond naturally. {guidance}"
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
                "temperature": 0.9,
            },
            timeout=30,
        )

        response.raise_for_status()
        reply = response.json()["choices"][0]["message"]["content"].strip()

        # collect last honeypot replies to prevent loops
        recent_replies = [
            msg["text"] for msg in conversation[-3:]
            if msg.get("sender") == "honeypot"
        ]

        return sanitize_reply(reply, recent_replies)

    except requests.exceptions.RequestException as e:
        print("⚠️ OpenRouter request failed:", e)
        return "Network thoda slow hai… ek minute ruk sakte ho?"
