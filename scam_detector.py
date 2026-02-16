import re
from typing import List, Tuple

# Scam indicator patterns and keywords
URGENCY_KEYWORDS = [
    "urgent", "immediately", "today", "now", "quick", "fast", "hurry",
    "limited time", "expires", "deadline", "asap", "right away", "don't delay",
    "act now", "warning", "alert", "important", "critical"
]

THREAT_KEYWORDS = [
    "blocked", "suspended", "deactivated", "terminated", "closed", "frozen",
    "seized", "legal action", "police", "court", "arrest", "fine", "penalty",
    "will be blocked", "account blocked", "account suspended"
]

FINANCIAL_KEYWORDS = [
    "bank", "account", "upi", "payment", "transfer", "money", "rupees", "rs",
    "balance", "transaction", "kyc", "verify", "verification", "update",
    "otp", "pin", "cvv", "card", "atm", "ifsc", "neft", "rtgs", "imps"
]

REWARD_KEYWORDS = [
    "won", "winner", "prize", "lottery", "reward", "cashback", "bonus",
    "free", "gift", "offer", "lucky", "congratulations", "selected", "chosen"
]

IMPERSONATION_KEYWORDS = [
    "rbi", "reserve bank", "government", "ministry", "income tax", "it department",
    "sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "gpay", "google pay",
    "customer care", "support", "helpline", "official"
]

ACTION_KEYWORDS = [
    "click", "link", "call", "contact", "share", "send", "provide", "enter",
    "submit", "confirm", "verify", "update", "download", "install"
]

INVESTMENT_KEYWORDS = [
    "invest", "bitcoin", "crypto", "trading", "returns", "profit", "guaranteed",
    "double", "forex", "scheme", "mutual fund", "stock", "portfolio",
    "high returns", "risk free", "guaranteed returns", "cryptocurrency"
]

JOB_KEYWORDS = [
    "job offer", "work from home", "salary", "hiring", "interview", "recruitment",
    "part time", "full time", "earn from home", "online job", "vacancy",
    "registration fee", "joining fee", "data entry"
]

def detect_scam(text: str, conversation_history: List[dict] = None) -> Tuple[bool, List[str]]:
    """
    Analyze text for scam indicators.
    Returns (is_scam, list_of_detected_keywords)
    """
    text_lower = text.lower()
    detected_keywords = []
    scam_score = 0
    
    # Check urgency patterns
    for keyword in URGENCY_KEYWORDS:
        if keyword in text_lower:
            detected_keywords.append(keyword)
            scam_score += 2
    
    # Check threat patterns
    for keyword in THREAT_KEYWORDS:
        if keyword in text_lower:
            detected_keywords.append(keyword)
            scam_score += 3
    
    # Check financial patterns
    for keyword in FINANCIAL_KEYWORDS:
        if keyword in text_lower:
            detected_keywords.append(keyword)
            scam_score += 1
    
    # Check reward patterns
    for keyword in REWARD_KEYWORDS:
        if keyword in text_lower:
            detected_keywords.append(keyword)
            scam_score += 2
    
    # Check impersonation patterns
    for keyword in IMPERSONATION_KEYWORDS:
        if keyword in text_lower:
            detected_keywords.append(keyword)
            scam_score += 2
    
    # Check action request patterns
    for keyword in ACTION_KEYWORDS:
        if keyword in text_lower:
            detected_keywords.append(keyword)
            scam_score += 1
    
    # Check investment/crypto patterns
    for keyword in INVESTMENT_KEYWORDS:
        if keyword in text_lower:
            detected_keywords.append(keyword)
            scam_score += 2
    
    # Check job scam patterns
    for keyword in JOB_KEYWORDS:
        if keyword in text_lower:
            detected_keywords.append(keyword)
            scam_score += 2
    
    # Check for URLs (often suspicious)
    url_pattern = r'https?://[^\s]+'
    if re.search(url_pattern, text_lower):
        detected_keywords.append("contains_url")
        scam_score += 2
    
    # Check for phone numbers
    phone_pattern = r'[\+]?[0-9]{10,12}'
    if re.search(phone_pattern, text):
        detected_keywords.append("contains_phone")
        scam_score += 1
    
    # Check for UPI ID patterns
    upi_pattern = r'[a-zA-Z0-9._-]+@[a-zA-Z]+'
    if re.search(upi_pattern, text_lower):
        detected_keywords.append("contains_upi")
        scam_score += 2
    
    # Analyze conversation history for cumulative patterns
    if conversation_history:
        history_text = " ".join([msg.get("text", "") for msg in conversation_history])
        history_lower = history_text.lower()
        
        # Check if conversation is building up scam pattern
        financial_mentions = sum(1 for kw in FINANCIAL_KEYWORDS if kw in history_lower)
        if financial_mentions >= 2:
            scam_score += 2
    
    # Scam threshold - if score >= 3, consider it a scam
    is_scam = scam_score >= 3
    
    return is_scam, list(set(detected_keywords))

def get_scam_type(keywords: List[str]) -> str:
    """Determine the type of scam based on detected keywords."""
    if any(kw in keywords for kw in ["kyc", "verify", "verification", "update"]):
        return "KYC_FRAUD"
    elif any(kw in keywords for kw in ["won", "winner", "prize", "lottery", "reward"]):
        return "LOTTERY_SCAM"
    elif any(kw in keywords for kw in ["blocked", "suspended", "deactivated"]):
        return "ACCOUNT_THREAT"
    elif any(kw in keywords for kw in ["otp", "pin", "cvv"]):
        return "OTP_FRAUD"
    elif any(kw in keywords for kw in ["contains_url"]):
        return "PHISHING"
    elif any(kw in keywords for kw in ["invest", "bitcoin", "crypto", "trading", "returns", "profit", "guaranteed"]):
        return "INVESTMENT_SCAM"
    elif any(kw in keywords for kw in ["job offer", "work from home", "hiring", "recruitment", "salary"]):
        return "JOB_SCAM"
    else:
        return "GENERAL_FRAUD"
