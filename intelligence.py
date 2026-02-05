import re
from typing import List
from models import ExtractedIntelligence

def extract_bank_accounts(text: str) -> List[str]:
    """Extract potential bank account numbers (10-18 digits)."""
    patterns = [
        r'(?:account|a/c|ac)[\s:.-]*(\d{10,18})',  # After "account" keyword
        r'\b(\d{10,18})\b',  # Generic account number
        r'(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{0,6})',  # With separators
    ]
    accounts = []
    for pattern in patterns:
        matches = re.findall(pattern, text.lower())
        for match in matches:
            # Clean and validate
            clean = re.sub(r'[-\s]', '', match)
            if len(clean) >= 10 and len(clean) <= 18:
                # Only exclude if EXACTLY 10 digits AND starts with 6-9 (phone number)
                if len(clean) == 10 and clean[0] in '6789':
                    continue  # Skip phone numbers
                accounts.append(clean)
    return list(set(accounts))

def extract_upi_ids(text: str) -> List[str]:
    """Extract UPI IDs in format user@bank."""
    pattern = r'[a-zA-Z0-9._-]+@[a-zA-Z]{2,}'
    matches = re.findall(pattern, text.lower())
    
    # Filter out email-like patterns (they usually have longer domains)
    upi_suffixes = ['upi', 'ybl', 'okhdfcbank', 'okaxis', 'oksbi', 'okicici', 
                    'paytm', 'apl', 'rapl', 'ibl', 'axl', 'sbi', 'icici', 
                    'hdfc', 'axis', 'kotak', 'boi', 'pnb', 'bob', 'canara',
                    'fbl', 'federal', 'idfcfirst', 'indus', 'kvb', 'rbl',
                    'airtel', 'jio', 'slice', 'fi', 'jupiter', 'cred']
    
    upi_ids = []
    for match in matches:
        # Check if it looks like a UPI ID (short suffix, not email domain)
        parts = match.split('@')
        if len(parts) == 2:
            suffix = parts[1].lower()
            # UPI suffixes are usually short (2-12 chars) or match known patterns
            if len(suffix) <= 12 or any(s in suffix for s in upi_suffixes):
                upi_ids.append(match)
    
    return list(set(upi_ids))

def extract_phone_numbers(text: str) -> List[str]:
    """Extract Indian phone numbers."""
    patterns = [
        r'\+91[-\s]?[6-9]\d{9}',  # With country code
        r'\b[6-9]\d{9}\b',  # Without country code
        r'\b91[6-9]\d{9}\b',  # With 91 prefix no plus
    ]
    
    phones = []
    for pattern in patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            clean = re.sub(r'[-\s]', '', match)
            if clean.startswith('+'):
                phones.append(clean)
            elif clean.startswith('91') and len(clean) == 12:
                phones.append('+' + clean)
            elif len(clean) == 10:
                phones.append('+91' + clean)
    
    return list(set(phones))

def extract_urls(text: str) -> List[str]:
    """Extract URLs/phishing links."""
    pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
    matches = re.findall(pattern, text)
    
    # Also capture shortened/obfuscated URLs
    short_pattern = r'(?:bit\.ly|tinyurl|goo\.gl|t\.co|rb\.gy|cutt\.ly|shorturl)[/][^\s]+'
    short_matches = re.findall(short_pattern, text.lower())
    
    # Capture potential dots without http
    dot_pattern = r'\b\w+\.\w+/[^\s]*'
    dot_matches = re.findall(dot_pattern, text)
    
    all_urls = matches + short_matches + dot_matches
    return list(set(all_urls))

def extract_suspicious_keywords(text: str) -> List[str]:
    """Extract suspicious keywords from text."""
    keywords = []
    text_lower = text.lower()
    
    suspicious_terms = [
        "urgent", "immediately", "blocked", "suspended", "verify", 
        "kyc", "otp", "pin", "update", "click", "link", "won", 
        "prize", "lottery", "reward", "free", "account", "bank",
        "transfer", "payment", "money", "upi", "customer care",
        "helpline", "support", "official", "government", "rbi"
    ]
    
    for term in suspicious_terms:
        if term in text_lower:
            keywords.append(term)
    
    return list(set(keywords))

def extract_all_intelligence(text: str, existing: ExtractedIntelligence = None) -> ExtractedIntelligence:
    """Extract all intelligence from text and merge with existing."""
    new_intel = ExtractedIntelligence(
        bankAccounts=extract_bank_accounts(text),
        upiIds=extract_upi_ids(text),
        phishingLinks=extract_urls(text),
        phoneNumbers=extract_phone_numbers(text),
        suspiciousKeywords=extract_suspicious_keywords(text)
    )
    
    if existing:
        # Merge with existing intelligence
        return ExtractedIntelligence(
            bankAccounts=list(set(existing.bankAccounts + new_intel.bankAccounts)),
            upiIds=list(set(existing.upiIds + new_intel.upiIds)),
            phishingLinks=list(set(existing.phishingLinks + new_intel.phishingLinks)),
            phoneNumbers=list(set(existing.phoneNumbers + new_intel.phoneNumbers)),
            suspiciousKeywords=list(set(existing.suspiciousKeywords + new_intel.suspiciousKeywords))
        )
    
    return new_intel

def extract_from_conversation(messages: List[dict]) -> ExtractedIntelligence:
    """Extract intelligence from entire conversation history."""
    intel = ExtractedIntelligence()
    
    for msg in messages:
        text = msg.get("text", "")
        intel = extract_all_intelligence(text, intel)
    
    return intel
