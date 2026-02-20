
import re
from typing import List, Dict, Optional, Set


# Convert digit words -> numbers
DIGIT_WORDS = {
    "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4",
    "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9"
}


def convert_digit_words(text: str) -> str:
    pattern = re.compile(r"\b(" + "|".join(DIGIT_WORDS.keys()) + r")\b", re.IGNORECASE)
    return pattern.sub(lambda match: DIGIT_WORDS[match.group().lower()], text)


def normalize_obfuscation(text: str) -> str:
    """Convert common character substitutions scammers use.

    Important: apply substitutions only inside *number-like* spans.
    We must not translate normal words globally (e.g., "or" -> "0r", "to" -> "t0"),
    which can create phantom digits and break extraction.
    """

    # Only map characters typically used to visually spoof digits.
    replacements = str.maketrans({
        "O": "0", "o": "0",
        "I": "1", "l": "1",
        "S": "5", "s": "5",
    })

    # Match spans that already contain at least one digit and otherwise look like a phone-ish chunk.
    # This excludes plain words like "or"/"to" while still catching e.g. "98O65l4321O".
    span_pattern = re.compile(
        r"(?<!\w)(?=[0-9OoIlSs\s\-()./]{6,})(?=.*\d)[0-9OoIlSs\s\-()./]{6,}(?!\w)"
    )

    def _translate_span(match: re.Match) -> str:
        return match.group(0).translate(replacements)

    return span_pattern.sub(_translate_span, text)


def extract_phone_numbers(text: str):
    def is_obfuscated_split(number: str) -> bool:
        groups = re.findall(r"\d+", number)
        # Typical obfuscation: many short digit groups (e.g., "98 76 54 32 10" or "9 8 7 ...").
        return len(groups) >= 4 and all(len(group) <= 2 for group in groups)

    def clean_candidate(candidate: str) -> Optional[str]:
        # Trim trailing punctuation that often follows numbers in sentences.
        stripped = candidate.strip().strip(",;:")
        digits = re.sub(r"\D", "", stripped)
        if not (8 <= len(digits) <= 15):
            return None

        if is_obfuscated_split(stripped):
            return ("+" + digits) if stripped.startswith("+") else digits

        return stripped

    numbers: Set[str] = set()

    # 1) Extract from the original text (preserve formatting for normal human-written formats).
    # General pattern: starts with optional '+' or '(' then digits and allowed separators, ends with a digit.
    general_pattern = re.compile(r"(?<!\w)(\+?\(?\d[\d\s\-()./]{6,}\d\)?)(?!\w)")
    for match in general_pattern.findall(text):
        cleaned = clean_candidate(match)
        if cleaned:
            numbers.add(cleaned)

    # 2) Normalize only within number-like spans to catch hidden/obfuscated embeddings,
    #    then run the same extractor.
    normalized_text = convert_digit_words(normalize_obfuscation(text))
    for match in general_pattern.findall(normalized_text):
        cleaned = clean_candidate(match)
        if cleaned:
            numbers.add(cleaned)

    # 3) Numbers inside links (WhatsApp, tel, etc.)
    numbers.update(re.findall(r"(?:wa\.me/|tel:|\?phone=)(\+?\d{8,15})", normalized_text))

    # 4) Numbers inside UPI handles
    numbers.update(re.findall(r"(\d{8,15})@[a-zA-Z]+", normalized_text))

    return sorted(numbers)

def extract_intelligence(messages: List[Dict], store: dict):
    """Extract intelligence from scammer messages only"""
    
    # Use sets to prevent duplicates
    bank_accounts = set(store.get("bankAccounts", []))
    upi_ids = set(store.get("upiIds", []))
    phishing_links = set(store.get("phishingLinks", []))
    phone_numbers = set(store.get("phoneNumbers", []))
    email_addresses = set(store.get("emailAddresses", []))
    suspicious_keywords = set(store.get("suspiciousKeywords", []))
    
    # Extract only from messages with sender="scammer"
    scammer_text = " ".join(
        str(msg.get("text",""))
        for msg in messages
    )


    # Extract email addresses (must include a domain + TLD)
    # Use a strict token pattern to avoid capturing entire URLs that contain an email as a parameter.
    EMAIL_PATTERN = r"(?i)(?<![a-z0-9._%+\-])([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})(?![a-z0-9._%+\-])"

    matches = re.findall(EMAIL_PATTERN, scammer_text)

    # normalize
    for email in matches:
        email = email.lower().strip().strip(",;:.")
        email_addresses.add(email)
    
    # Extract UPI IDs (handle is usually not a full email domain)
    upi_matches = re.findall(r"\b[a-zA-Z0-9._-]{2,}@[a-zA-Z0-9._-]{2,}\b", scammer_text)
    upi_ids.update(match for match in upi_matches if "." not in match.split("@", 1)[1])
    
    # Extract bank account numbers (12-18 digits to avoid phone numbers)
    accounts = re.findall(r"\b\d{12,18}\b", scammer_text)
    bank_accounts.update(accounts)
    
    # Extract globally formatted phone numbers (with obfuscation normalization)
    phone_numbers.update(extract_phone_numbers(scammer_text))
    
    # Extract URLs
    links = re.findall(r"https?://[^\s]+", scammer_text)
    phishing_links.update(links)
    
    # Extract suspicious keywords
    keywords = ["urgent", "verify", "blocked", "otp", "suspend", "freeze", "compromise", "expire", "immediate"]
    for word in keywords:
        if word in scammer_text.lower():
            suspicious_keywords.add(word)
    
    # Update store with sorted, unique values
    store["bankAccounts"] = sorted(list(bank_accounts))
    store["upiIds"] = sorted(list(upi_ids))
    store["phishingLinks"] = sorted(list(phishing_links))
    store["phoneNumbers"] = sorted(list(phone_numbers))
    store["emailAddresses"] = sorted(list(email_addresses))
    store["suspiciousKeywords"] = sorted(list(suspicious_keywords))
