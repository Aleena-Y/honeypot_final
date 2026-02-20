
import re
from typing import List, Dict

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
    scammer_text = " ".join([msg["text"] for msg in messages if msg.get("sender", "").lower() == "scammer"])
    
    if not scammer_text:
        return

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
    
    # Extract phone numbers (Indian format with optional separators)
    phones = re.findall(r"(?:\+91[-\s]?)?[6-9]\d{9}\b", scammer_text)
    normalized_phones = [re.sub(r"[\s-]", "", phone).strip() for phone in phones]
    phone_numbers.update(normalized_phones)
    
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
