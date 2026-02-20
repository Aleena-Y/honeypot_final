import re

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
