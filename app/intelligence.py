
import re
from typing import List, Dict


# Convert digit words -> numbers
DIGIT_WORDS = {
    "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4",
    "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9"
}


def convert_digit_words(text: str) -> str:
    pattern = re.compile(r"\b(" + "|".join(DIGIT_WORDS.keys()) + r")\b", re.IGNORECASE)
    return pattern.sub(lambda match: DIGIT_WORDS[match.group().lower()], text)


def normalize_obfuscation(text: str) -> str:
    """Convert common character substitutions scammers use."""
    replacements = str.maketrans({
        "O": "0", "o": "0",
        "I": "1", "l": "1",
        "S": "5"
    })
    return text.translate(replacements)


def extract_phone_numbers(text: str):
    text = normalize_obfuscation(text)
    text = convert_digit_words(text)

    numbers = set()

    # Numbers inside links (WhatsApp, tel, etc.)
    numbers.update(re.findall(r"(?:wa\.me/|tel:|\?phone=)(\+?\d{8,15})", text))

    # Numbers inside UPI handles
    numbers.update(re.findall(r"(\d{8,15})@[a-zA-Z]+", text))

    # General global phone formats
    pattern = r"""
        (?<!\w)
        (?:\+?\d{1,3}[\s\-()./]*)?     # optional country code
        (?:\(?\d{2,4}\)?[\s\-()./]*)?  # optional area code
        \d{2,4}[\s\-()./]*\d{2,4}[\s\-()./]*\d{2,4}
        (?!\w)
    """

    matches = re.findall(pattern, text, re.VERBOSE)

    for match in matches:
        digits = re.sub(r"\D", "", match)
        if 8 <= len(digits) <= 15:
            numbers.add(digits)

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
    # Generalized email extraction
    EMAIL_PATTERN = r"(?<![\w@])([^\s@]+@[^\s@]+\.[^\s@]+)"

    matches = re.findall(EMAIL_PATTERN, scammer_text)

    # normalize & validate
    for email in matches:
        email = email.lower().strip()

        # basic validation to reduce noise
        if email.count("@") == 1 and "." in email.split("@")[1]:
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
