
from __future__ import annotations

from typing import Dict, List


# Scenario keywords (keep these lower-case; matching is done on lower-cased text)
BANK_FRAUD = [
    "account blocked", "account suspended", "unauthorized transaction",
    "verify bank account", "bank verification", "fraud detected",
    "suspicious transaction", "secure your account",
    "login to avoid suspension", "bank security alert",
]

UPI_FRAUD = [
    "collect request", "approve request", "upi blocked",
    "upi verification", "payment request", "request pending",
    "receive money", "accept payment", "upi suspend",
    "scan to receive", "verify upi",
]

PHISHING_SCAM = [
    "verify your account", "secure your account",
    "login to continue", "update details",
    "confirm identity", "click the link",
    "reset password", "avoid suspension",
    "validate account",
]

KYC_FRAUD = [
    "complete kyc", "kyc update", "re-kyc",
    "kyc expired", "kyc verification required",
    "update aadhaar", "update pan",
    "submit kyc", "kyc pending",
]

JOB_SCAM = [
    "work from home", "earn daily", "easy income",
    "part-time job", "online job", "registration fee",
    "training fee", "data entry job", "earn per day",
    "salary guarantee", "instant joining",
]

LOTTERY_SCAM = [
    "you won", "lottery winner", "claim prize",
    "lucky draw", "congratulations winner",
    "reward points", "cash prize",
    "claim reward", "winner selected",
]

ELECTRICITY_SCAM = [
    "electricity bill", "power disconnected",
    "bill overdue", "meter disconnected",
    "pay immediately", "supply will be cut",
    "last electricity notice",
]

GOVT_SCAM = [
    "government scheme", "subsidy approved",
    "benefit released", "pm scheme", "yojana benefit",
    "register to receive benefit", "apply now",
    "eligible beneficiary",
]

CRYPTO_SCAM = [
    "guaranteed profit", "double your money",
    "crypto investment", "bitcoin returns",
    "trading profit", "risk-free investment",
    "earn 5% daily", "high return investment",
]

PARCEL_SCAM = [
    "parcel held", "customs duty pending",
    "shipment held", "package on hold",
    "clear customs", "pay duty",
    "international parcel", "delivery clearance",
]

TECH_SUPPORT_SCAM = [
    "virus detected", "system infected",
    "technical support", "windows support",
    "device compromised", "remote access",
    "install support app", "security warning",
]

LOAN_SCAM = [
    "loan approved", "instant loan",
    "pre-approved loan", "no cibil check",
    "processing fee", "loan disbursement",
    "low interest loan",
]

TAX_SCAM = [
    "tax notice", "income tax notice",
    "tax penalty", "refund issued",
    "tax refund pending", "submit tax details",
    "tax verification required",
]

REFUND_SCAM = [
    "refund pending", "claim refund",
    "refund approved", "process refund",
    "return payment", "credit refund",
    "refund initiated",
]

INSURANCE_SCAM = [
    "policy expired", "renew policy",
    "insurance claim", "claim settlement",
    "premium overdue", "policy suspension",
    "insurance verification",
]

SOCIAL_MEDIA_SCAM = [
    "verify instagram", "facebook suspended",
    "whatsapp banned", "account recovery",
    "confirm your profile", "copyright violation",
]

ECOMMERCE_SCAM = [
    "order cancelled", "refund for order",
    "failed delivery", "confirm address",
    "update shipping", "order verification",
]

SIM_SCAM = [
    "sim blocked", "sim verification",
    "telecom verification", "reactivate sim",
    "number suspended", "sim upgrade",
]


SCAM_SCENARIOS: Dict[str, List[str]] = {
    "Bank Fraud": BANK_FRAUD,
    "UPI Fraud": UPI_FRAUD,
    "Phishing": PHISHING_SCAM,
    "KYC Fraud": KYC_FRAUD,
    "Job Scam": JOB_SCAM,
    "Lottery Scam": LOTTERY_SCAM,
    "Electricity Scam": ELECTRICITY_SCAM,
    "Government Scheme": GOVT_SCAM,
    "Crypto Scam": CRYPTO_SCAM,
    "Parcel Scam": PARCEL_SCAM,
    "Tech Support": TECH_SUPPORT_SCAM,
    "Loan Scam": LOAN_SCAM,
    "Tax Scam": TAX_SCAM,
    "Refund Scam": REFUND_SCAM,
    "Insurance Scam": INSURANCE_SCAM,
    "Social Media Scam": SOCIAL_MEDIA_SCAM,
    "Ecommerce Scam": ECOMMERCE_SCAM,
    "SIM Scam": SIM_SCAM,
}


def detect_scam_scenarios(text: str) -> Dict[str, List[str]]:
    lowered = (text or "").lower()
    detected: Dict[str, List[str]] = {}

    for scenario, keywords in SCAM_SCENARIOS.items():
        matches = [k for k in keywords if k in lowered]
        if matches:
            detected[scenario] = matches

    return detected


def detect_scam(text: str) -> bool:
    return bool(detect_scam_scenarios(text))
