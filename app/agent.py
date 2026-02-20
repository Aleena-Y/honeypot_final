import re
import requests
from app.config import OPENROUTER_API_KEY, OPENROUTER_MODEL

# Optional: known Indian UPI provider handles for precision
KNOWN_UPI_HANDLES = {
    "okhdfcbank","oksbi","okaxis","okicici",
    "ybl","ibl","axl","apl",
    "paytm","phonepe","gpay","amazonpay",
    "upi"
}

EMAIL_PATTERN = r"(?<![\w@])([^\s@]+@[^\s@]+\.[^\s@]+)"
UPI_PATTERN   = r"(?<!\w)([a-zA-Z0-9._-]{2,})@([a-zA-Z]{2,})(?!\.)"


def normalize_text(text: str) -> str:
    """
    Clean common obfuscation & spacing tricks used by scammers.
    """
    text = re.sub(r"\s*@\s*", "@", text)  # remove spaces around @
    text = re.sub(r"\s+", " ", text)      # collapse extra spaces
    return text


def extract_emails_and_upi(text: str):
    text = normalize_text(text)

    emails = set()
    upi_ids = set()

    # -------- Extract Emails --------
    email_matches = re.findall(EMAIL_PATTERN, text)

    for email in email_matches:
        email = email.lower().strip()

        # basic validation
        if email.count("@") != 1:
            continue

        local, domain = email.split("@")

        if "." in domain:
            emails.add(email)

    # -------- Extract UPI IDs --------
    upi_matches = re.findall(UPI_PATTERN, text)

    for user, handle in upi_matches:
        handle = handle.lower()
        upi = f"{user.lower()}@{handle}"

        # accept known handles OR handles without domain dots
        if handle in KNOWN_UPI_HANDLES or "." not in handle:
            upi_ids.add(upi)

    # remove overlap (if something classified as email)
    upi_ids = {u for u in upi_ids if u not in emails}

    return sorted(emails), sorted(upi_ids)


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
    return any(trigger in text.lower() for trigger in triggers)


def conversation_stage(conversation):
    length = len(conversation)

    if length < 3:
        return 1
    if length < 6:
        return 2
    if length < 9:
        return 3
    return 4


def build_guidance(conversation):
    history = " ".join(msg["text"].lower() for msg in conversation)
    last_msg = conversation[-1]["text"]

    asked_identity = any(word in history for word in ["department", "branch", "employee"])
    asked_verify = any(word in history for word in ["verify", "official", "website", "complaint"])
    asked_usage = any(word in history for word in ["use", "kyun", "kisliye", "why"])

    stage = conversation_stage(conversation)

    if scammer_requested_sensitive_info(last_msg):
        if stage == 1:
            return "Say you did not receive the message yet."
        if stage == 2:
            return "Say the message appeared but disappeared quickly."
        if stage == 3:
            return "Say digits are unclear due to network or screen issue."
        return "Say you are trying but the message keeps expiring."

    if not asked_identity:
        return "Ask which department or office they represent."
    if not asked_verify:
        return "Ask how you can verify they are official."
    if not asked_usage:
        return "Ask how sharing the OTP helps fix the problem."

    if stage == 3:
        return "Sound cooperative and say you are checking now."
    if stage == 4:
        return "Say you are trying but network delay is causing issues."

    return "Respond naturally."


def sanitize_reply(reply: str, recent_replies):
    lower_reply = reply.lower()

    dangerous_patterns = [
        "my otp", "sending otp", "otp is",
        "pin is", "account number is", "here is the code"
    ]

    if any(pattern in lower_reply for pattern in dangerous_patterns):
        reply = "Message clear nahi dikh raha… thoda ruk sakte ho?"

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
    messages.append({"role": "system", "content": f"Respond naturally. {guidance}"})

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

        recent_replies = [
            msg["text"] for msg in conversation[-3:]
            if msg.get("sender") == "honeypot"
        ]

        return sanitize_reply(reply, recent_replies)

    except requests.exceptions.RequestException as error:
        print("⚠️ OpenRouter request failed:", error)
        return "Network thoda slow hai… ek minute ruk sakte ho?"
