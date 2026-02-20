import re
import json
from typing import List, Dict, Set

# ─────────────────────────────────────────────────────────────────────────────
# 1. TEXT NORMALISATION
# ─────────────────────────────────────────────────────────────────────────────

_INVISIBLE = re.compile(
    r"[\u200b\u200c\u200d\u00ad\ufeff\u2060\u180e\u2028\u2029]"
)

_WORD_DIGIT_MAP = {
    "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4",
    "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9",
}
_WORD_DIGIT_RE = re.compile(
    r"\b(?:" + "|".join(_WORD_DIGIT_MAP.keys()) + r")\b", re.IGNORECASE
)

# Common fraud-leet substitutions only (keep alpha chars otherwise intact so
# IBAN detection on the same line is not corrupted)
_LEET_TABLE = str.maketrans({"O": "0", "o": "0", "l": "1", "I": "1",
                               "Z": "2", "z": "2"})


def _normalize(text: str) -> str:
    """Strip invisibles, convert word-digits, apply leet."""
    text = _INVISIBLE.sub("", text)
    text = _WORD_DIGIT_RE.sub(lambda m: _WORD_DIGIT_MAP[m.group().lower()], text)
    text = text.translate(_LEET_TABLE)
    return text


def _collapse_separators(text: str) -> str:
    """Remove spaces and dashes sitting *between* digit characters."""
    return re.sub(r"(?<=\d)[\s\-]+(?=\d)", "", text)


def _digit_sequences(line: str, min_len: int = 8) -> List[str]:
    """Return all digit runs of ≥ min_len after separator collapse."""
    return re.findall(r"\d{" + str(min_len) + r",}", _collapse_separators(line))


# ─────────────────────────────────────────────────────────────────────────────
# 2. IBAN VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

_IBAN_RE = re.compile(r"\b([A-Z]{2}\d{2}[A-Z0-9]{11,30})\b")


def _iban_valid(s: str) -> bool:
    if not (15 <= len(s) <= 34):
        return False
    rearranged = s[4:] + s[:4]
    numeric = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


def _extract_ibans(raw_line: str) -> List[str]:
    return [m.group(1) for m in _IBAN_RE.finditer(raw_line.upper())
            if _iban_valid(m.group(1))]


# ─────────────────────────────────────────────────────────────────────────────
# 3. LUHN CHECK (credit / debit cards)
# ─────────────────────────────────────────────────────────────────────────────

def _luhn(n: str) -> bool:
    digits = [int(d) for d in reversed(n)]
    total = sum(
        d if i % 2 == 0 else (2 * d - 9 if 2 * d > 9 else 2 * d)
        for i, d in enumerate(digits)
    )
    return total % 10 == 0


# ─────────────────────────────────────────────────────────────────────────────
# 4. CONTEXT SIGNALS
# ─────────────────────────────────────────────────────────────────────────────

_POSITIVE_CTX = re.compile(
    r"\b(account|acc|a/c|saving|current|beneficiary|neft|rtgs|imps|"
    r"escrow|nodal|deposit|transfer|wire|iban|swift|card|credit|debit|"
    r"primary|secondary|backup|virtual\s*(?:va)?|auto.?deposit|"
    r"pay|remit)\b",
    re.IGNORECASE,
)

_NEGATIVE_CTX = re.compile(
    r"\b(ticket|tracking[\s\-]?id|order[\s\-]?ref|invoice|"
    r"date[\s\-]of[\s\-]birth|dob|airway\s*bill|awb|"
    r"mobile[\s\-]contact|support[\s\-]phone|complaint|"
    r"cancelled|unreachable|sms[\s\-]order)\b",
    re.IGNORECASE,
)


# ─────────────────────────────────────────────────────────────────────────────
# 5. SUSPICIOUS KEYWORDS
# ─────────────────────────────────────────────────────────────────────────────

_SUSPICIOUS_VOCAB = [
    "urgent", "immediate", "attention required",
    "blocked", "expire", "kyc",
    "winning", "winnings", "prize", "lottery",
    "clearance fee", "processing fee", "release fee",
    "funds", "deposit", "wire",
    "neft", "rtgs", "imps",
    "escrow", "nodal", "virtual",
    "authorized", "banking channel",
    "transfer", "remit",
]
_KW_RE = re.compile(
    r"\b(?:" + "|".join(
        re.escape(k) for k in sorted(_SUSPICIOUS_VOCAB, key=len, reverse=True)
    ) + r")\b",
    re.IGNORECASE,
)


# ─────────────────────────────────────────────────────────────────────────────
# 6. MAIN EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────

def extract_intelligence(messages: List[Dict], store: Dict) -> None:
    """
    Parameters
    ----------
    messages : list of dicts, each with at least a 'text' key
    store    : dict that will be populated with the six intelligence fields
    """
    bank_accounts:       Set[str] = set()
    upi_ids:             Set[str] = set()
    phishing_links:      Set[str] = set()
    phone_numbers:       Set[str] = set()
    email_addresses:     Set[str] = set()
    suspicious_keywords: Set[str] = set()

    for msg in messages:
        raw: str = msg.get("text", "")

        # ── Email addresses ────────────────────────────────────────────────────
        email_addresses.update(
            re.findall(
                r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", raw
            )
        )

        # ── UPI IDs  (alphanumeric@bankhandle — no dot-separated TLD) ─────────
        for m in re.finditer(
            r"(?<![a-zA-Z0-9._%+\-])[a-zA-Z0-9.\-_+]{3,}@[a-zA-Z]{3,10}\b", raw
        ):
            candidate = m.group()
            # Must NOT look like a regular e-mail (no domain with dot-TLD)
            if not re.search(r"@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", candidate):
                upi_ids.add(candidate)

        # ── Phone numbers ──────────────────────────────────────────────────────
        for m in re.finditer(
            r"(?:\+\d{1,3}[\s\-]?)?\b\d{10}\b", raw
        ):
            phone_numbers.add(m.group().strip())

        # ── Phishing / suspicious URLs ─────────────────────────────────────────
        for url in re.findall(r"https?://[^\s'\"<>\]]+", raw, re.IGNORECASE):
            phishing_links.add(url.rstrip(".,)"))
        for url in re.findall(
            r"(?:www\.|bit\.ly/|tinyurl\.com/|t\.me/|telegram\.me/)[^\s'\"<>\]]+",
            raw, re.IGNORECASE
        ):
            phishing_links.add(url.rstrip(".,)"))

        # ── Suspicious keywords ────────────────────────────────────────────────
        for m in _KW_RE.finditer(raw):
            suspicious_keywords.add(m.group().lower())

        # ── Bank accounts (context-aware, line-by-line) ────────────────────────
        for line in raw.split("\n"):
            line = line.strip()
            if not line:
                continue

            has_pos = bool(_POSITIVE_CTX.search(line))
            has_neg = bool(_NEGATIVE_CTX.search(line))

            # Skip lines that lack financial context OR carry reference/noise signals
            if not has_pos or has_neg:
                continue

            # --- IBANs (from raw line, case-insensitive uppercase match) -------
            ibans = _extract_ibans(line)
            bank_accounts.update(ibans)

            # --- Obfuscated domestic / card numbers ----------------------------
            # (Skip if IBANs were already extracted to avoid digit sub-sequences)
            if not ibans:
                processed = _normalize(line)
                for seq in _digit_sequences(processed, min_len=8):
                    if 13 <= len(seq) <= 19 and _luhn(seq):
                        # Valid card number
                        bank_accounts.add(seq)
                    elif 8 <= len(seq) <= 20:
                        # Domestic account number (Indian: 9–18 digits)
                        bank_accounts.add(seq)

    store["bankAccounts"]       = sorted(bank_accounts)
    store["upiIds"]             = sorted(upi_ids)
    store["phishingLinks"]      = sorted(phishing_links)
    store["phoneNumbers"]       = sorted(phone_numbers)
    store["emailAddresses"]     = sorted(email_addresses)
    store["suspiciousKeywords"] = sorted(suspicious_keywords)