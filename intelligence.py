import re
import logging
from typing import List
from models import ExtractedIntelligence

# Pre-compiled patterns for performance (Phase 1 Optimization)
URL_PATTERN = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
PHONE_PATTERN = re.compile(r'\b(?:\+91|91)?[6-9]\d{9}\b')
UPI_PATTERN = re.compile(r'[a-zA-Z0-9.\-_]+@[a-zA-Z]{3,}')
BANK_ACCOUNT_PATTERN = re.compile(r'\b\d{9,18}\b')

def extract_bank_accounts(text: str) -> List[str]:
    """Extract potential bank account numbers (10-18 digits)."""
    matches = BANK_ACCOUNT_PATTERN.findall(text)
    
    # Filter out likely phone numbers (10 digits starting with 6-9)
    # Using stricter logic to differentiate
    filtered = []
    for m in matches:
        if len(m) == 10 and m[0] in '6789':
            continue # Likely a phone number
        filtered.append(m)
        
    return list(set(filtered))

def extract_upi_ids(text: str) -> List[str]:
    """Extract UPI IDs."""
    return list(set(UPI_PATTERN.findall(text)))

def extract_phishing_links(text: str) -> List[str]:
    """Extract suspicious URLs."""
    return list(set(URL_PATTERN.findall(text)))

def extract_phone_numbers(text: str) -> List[str]:
    """Extract Indian phone numbers."""
    matches = PHONE_PATTERN.findall(text)
    normalized = []
    
    for m in matches:
        # Check if it starts with 91 but no plus
        if m.startswith('91') and len(m) == 12:
            normalized.append('+' + m)
        elif len(m) == 10:
            normalized.append('+91' + m)
        else:
            normalized.append(m)
            
    return list(set(normalized))

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
        phishingLinks=extract_phishing_links(text),
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
