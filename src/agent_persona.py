"""
Honeypot Agent Persona — Smart Response Engine
Uses the comprehensive response dataset with context-aware selection.

Persona: Ramesh Kumar, 52-year-old retired govt employee
Selection: scam_type → category mapping → phase-based → random from pool
Features: language detection, deduplication, red-flag identification, probing questions
"""
import random
import logging
from typing import List, Optional
from response_dataset import RESPONSE_DB
from hinglish_dataset import HINGLISH_DB

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────
# Keep English and Hinglish pools SEPARATE for language matching
# ─────────────────────────────────────────────────────────────────────────

# Hindi/Hinglish characters and common words for detection
HINDI_MARKERS = set("अआइईउऊएऐओऔकखगघचछजझटठडढणतथदधनपफबभमयरलवशषसह")
HINGLISH_WORDS = {
    "hai", "hain", "nahi", "kya", "kaise", "kahan", "kaun", "kyun", "bhai",
    "ji", "mera", "meri", "mere", "tera", "teri", "tere", "aapka", "aapki",
    "yeh", "woh", "abhi", "bolo", "batao", "karo", "karna", "hona", "raha",
    "rahi", "rahe", "toh", "bhi", "aur", "par", "lekin", "pehle", "baad",
    "mein", "ko", "ka", "ki", "ke", "se", "pe", "ne", "sir", "madam",
    "arrey", "theek", "accha", "haan", "nahin", "chahiye", "dijiye", "dena",
    "lena", "jaana", "aana", "paisa", "rupee", "lakh", "crore", "sahib",
    "beta", "beti", "bhai", "didi", "uncle", "aunty", "sahab",
}


def _detect_language(text: str) -> str:
    """Detect if message is English or Hinglish based on content."""
    # Check for Devanagari script
    if any(c in HINDI_MARKERS for c in text):
        return "hinglish"

    # Check for common Hinglish words
    words = set(text.lower().split())
    hinglish_count = len(words & HINGLISH_WORDS)
    if hinglish_count >= 2:
        return "hinglish"

    return "english"


def _get_pool(category: str, phase: str, language: str) -> list:
    """Get the response pool matching category, phase, and language."""
    if language == "hinglish":
        pool = HINGLISH_DB.get(category, {}).get(phase, [])
        if pool:
            return pool
        # Fallback to English if Hinglish pool empty for this category
        return RESPONSE_DB.get(category, {}).get(phase, [])
    else:
        pool = RESPONSE_DB.get(category, {}).get(phase, [])
        if pool:
            return pool
        # Fallback to Hinglish if English pool empty
        return HINGLISH_DB.get(category, {}).get(phase, [])

# ─────────────────────────────────────────────────────────────────────────
# Map scam types (from scam_detector.py) → response database categories
# ─────────────────────────────────────────────────────────────────────────

SCAM_TYPE_TO_CATEGORY = {
    "KYC_FRAUD":        "kyc_fraud",
    "ACCOUNT_THREAT":   "account_threat",
    "OTP_FRAUD":        "otp_fraud",
    "LOTTERY_SCAM":     "lottery_scam",
    "INVESTMENT_SCAM":  "investment_scam",
    "PHISHING":         "phishing",
    "UPI_FRAUD":        "payment_request",
    "BANK_FRAUD":       "account_threat",
    "GENERAL_FRAUD":    "general",
    # New scam types
    "JOB_SCAM":         "job_scam",
    "INSURANCE_SCAM":   "insurance_scam",
    "TAX_SCAM":         "tax_scam",
    "CUSTOMS_SCAM":     "customs_scam",
    "ELECTRICITY_SCAM": "electricity_scam",
    "REFUND_SCAM":      "refund_scam",
    "GOVT_SCAM":        "govt_scam",
}

# ─────────────────────────────────────────────────────────────────────────
# Keyword-based category detection (supplements scam_type for precision)
# ─────────────────────────────────────────────────────────────────────────

def _detect_category(text: str) -> str:
    """Detect the best response category from message content."""
    t = text.lower()

    # OTP/PIN/CVV — highest priority (most dangerous)
    if any(w in t for w in ["otp", "pin", "cvv", "password", "code", "one time", "verification code"]):
        return "otp_fraud"

    # Threats and legal pressure
    if any(w in t for w in ["arrest", "police", "legal", "court", "jail", "fine", "penalty",
                             "case filed", "fir", "warrant", "summon"]):
        return "tax_scam"  # threats usually come from fake govt/police

    # Investment / crypto
    if any(w in t for w in ["invest", "bitcoin", "crypto", "trading", "returns", "profit",
                             "guaranteed", "mutual fund", "stock", "forex", "doubl"]):
        return "investment_scam"

    # Lottery / prize / reward
    if any(w in t for w in ["won", "winner", "prize", "lottery", "reward", "congratulat",
                             "selected", "lucky", "cashback", "gift"]):
        return "lottery_scam"

    # Job / work-from-home
    if any(w in t for w in ["job", "work from home", "part time", "earn", "hiring",
                             "vacancy", "resume", "salary", "registration fee"]):
        return "job_scam"

    # Insurance / policy
    if any(w in t for w in ["insurance", "policy", "lic", "premium", "maturity",
                             "claim", "nominee", "endowment", "irda"]):
        return "insurance_scam"

    # Delivery / courier / customs
    if any(w in t for w in ["deliver", "courier", "package", "parcel", "customs",
                             "shipment", "tracking", "dispatch", "consignment",
                             "seized", "narcotics", "drugs", "ndps"]):
        return "customs_scam" if any(w in t for w in ["customs", "seized", "narcotics", "ndps"]) else "delivery_scam"

    # Tech support / remote access
    if any(w in t for w in ["virus", "hack", "malware", "computer", "laptop",
                             "microsoft", "remote", "teamviewer", "anydesk"]):
        return "tech_support"

    # Electricity / utility
    if any(w in t for w in ["electricity", "power", "bijli", "discom", "meter",
                             "bill overdue", "disconnection", "power cut"]):
        return "electricity_scam"

    # Government scheme
    if any(w in t for w in ["government scheme", "pm scheme", "subsidy", "housing scheme",
                             "pradhan mantri", "ministry", "ration", "aadhar"]):
        return "govt_scam"

    # Refund
    if any(w in t for w in ["refund", "reprocess", "failed transaction", "compensation"]):
        return "refund_scam"

    # Loan / credit
    if any(w in t for w in ["loan", "credit card", "emi", "cibil", "pre-approved",
                             "disburse", "sanction", "processing fee"]):
        return "loan_scam"

    # Romance / relationship
    if any(w in t for w in ["dear", "beloved", "love", "marry", "relationship",
                             "lonely", "heart", "dating", "soul"]):
        return "romance_scam"

    # Payment / money transfer
    if any(w in t for w in ["pay", "send money", "transfer", "amount", "rupee",
                             "rs ", "rs.", "fee", "charge", "upi", "cashback"]):
        return "payment_request"

    # KYC / verification
    if any(w in t for w in ["kyc", "verify", "update", "document", "aadhaar",
                             "pan", "aadhar", "identity"]):
        return "kyc_fraud"

    # Phishing links
    if any(w in t for w in ["click", "link", "url", "website", "download",
                             "http", "www", "log in", "login"]):
        return "phishing"

    # Account block / urgency
    if any(w in t for w in ["block", "suspend", "urgent", "immediately",
                             "deactivat", "frozen", "expire", "terminat"]):
        return "account_threat"

    return "general"


def _get_phase(turn_count: int) -> str:
    """Determine conversation phase from turn count."""
    if turn_count <= 2:
        return "early"     # Turns 1-2: confused, scared
    elif turn_count <= 6:
        return "middle"    # Turns 3-6: cooperative, extracting intel
    else:
        return "late"      # Turns 7+: stalling, squeezing last details


# ─────────────────────────────────────────────────────────────────────────
# Red-flag detection & probing question generation
# ─────────────────────────────────────────────────────────────────────────

def _detect_red_flag(text: str) -> str:
    """Identify the most relevant red flag in the scammer's message."""
    t = text.lower()
    if any(w in t for w in ["otp", "pin", "cvv", "password"]):
        return "Requesting sensitive credentials (OTP/PIN/CVV) — legitimate banks never ask for these"
    if any(w in t for w in ["account number", "card number", "16-digit", "debit card", "credit card"]):
        return "Requesting account/card number — legitimate banks already have this on file"
    if any(w in t for w in ["blocked", "suspended", "deactivated", "frozen"]):
        return "Account threat/pressure tactic — creating urgency to bypass rational thinking"
    if any(w in t for w in ["urgent", "immediately", "right now", "right away", "within 2 hours", "last chance"]):
        return "Artificial time pressure — scammers create urgency to prevent verification"
    if any(w in t for w in ["arrest", "police", "legal", "fir", "warrant", "court order"]):
        return "Legal intimidation — fake authority threats to coerce compliance"
    if any(w in t for w in ["won", "winner", "prize", "lottery", "reward"]):
        return "Unsolicited prize — classic advance-fee fraud pattern"
    if any(w in t for w in ["invest", "guaranteed", "returns", "profit", "doubl"]):
        return "Guaranteed returns promise — no legitimate investment guarantees profits"
    if any(w in t for w in ["http", "www", "click", "link"]):
        return "Suspicious URL shared — potential phishing link to steal credentials"
    if any(w in t for w in ["kyc", "update your", "verify your", "verification required"]):
        return "KYC/verification request via phone/message — banks do KYC in-branch only"
    if any(w in t for w in ["transfer", "send money", "pay", "fee", "charge", "penalty"]):
        return "Requesting money transfer — legitimate services don't ask for upfront payments this way"
    if any(w in t for w in ["whatsapp", "telegram", "personal number"]):
        return "Moving to personal messaging — attempting to evade official communication channels"
    if any(w in t for w in ["reply", "confirm", "submit", "provide", "share your"]):
        return "Requesting personal information via unsecured channel — potential social engineering"
    if any(w in t for w in ["refund", "cashback", "compensation"]):
        return "Refund bait — creating false hope to extract banking credentials"
    if any(w in t for w in ["final", "warning", "terminat", "cancel"]):
        return "Escalation threat — increasing pressure to force immediate compliance"
    if any(w in t for w in ["customs", "seized", "parcel"]):
        return "Customs seizure threat — fake authority claim to extort payment"
    if any(w in t for w in ["electricity", "power cut", "disconnection"]):
        return "Utility disconnection threat — creating urgency around essential services"
    if any(w in t for w in ["job", "hiring", "work from home"]):
        return "Fake job offer — employment bait requiring upfront registration fees"
    return ""


# ─── Probing questions grouped by intel target (40 total) ─────────────────
_PROBE_BY_TARGET = {
    "email": [
        "By the way, what is your official email ID? I want to send you a written complaint.",
        "Can you email me the official notice? What's your bank's official email domain?",
        "I prefer communication by email. Share your official email — what is it exactly?",
        "My son says get everything in writing. Your official email please — what is it?",
        "Give me your email ID — I'll forward you the OTP screenshot for verification.",
        "My lawyer wants correspondence by email only. Share your official email address.",
        "For my records, what is your official email and your department head's email?",
    ],
    "phone": [
        "Can you give me a callback number? I'll call you back from my landline to confirm.",
        "What is your direct mobile number and your branch landline number for records?",
        "My son wants your direct phone number so he can call and verify this tomorrow.",
        "Share your WhatsApp number — I'll send you the documents there right away.",
        "Give me your phone number — I always call back before sharing any information.",
        "What is the toll-free number of your department? My son wants to call officially.",
    ],
    "upi": [
        "What UPI ID should I use if I need to make any payment for this matter?",
        "Share your UPI ID — PhonePe or Google Pay, what do you use for official payments?",
        "For the processing fee, what is the official UPI ID or QR code?",
        "My daughter wants to pay via UPI — what is the exact UPI handle I should use?",
        "Share the UPI ID of the department — I'll send the fine amount via PhonePe now.",
    ],
    "account": [
        "What is the bank account number and IFSC code for the fee payment? I'll do NEFT.",
        "Share your account details — account number, IFSC, and beneficiary name for transfer.",
        "Which account should I deposit to? Give me account number, branch name, and IFSC.",
        "For the demand draft, what is the payee name and bank account number exactly?",
        "My son will do RTGS — give the account number, IFSC code, and account holder name.",
    ],
    "identity": [
        "Can you share your employee ID and your supervisor's full name and phone number?",
        "What is your badge number and designation? I need it for my complaint letter.",
        "I need your full name, employee code, and the department you are calling from.",
        "My grandson is a cyber crime officer — share your ID details for his verification.",
        "What is your exact name and officer ID? I'm filling a complaint form right now.",
        "Share your name, designation, and department — I'm writing this in my diary.",
    ],
    "location": [
        "Which bank branch are you calling from? Give me the branch address and landline.",
        "What is the address of your office? My son wants to visit in person to verify.",
        "Share your branch name, address, and the branch manager's name for verification.",
        "Which city are you calling from? And the office address for postal communication?",
    ],
}

_PROBE_QUESTIONS = (
    _PROBE_BY_TARGET["email"] + _PROBE_BY_TARGET["phone"] +
    _PROBE_BY_TARGET["upi"] + _PROBE_BY_TARGET["account"] +
    _PROBE_BY_TARGET["identity"] + _PROBE_BY_TARGET["location"]
)


def _get_probing_question(text: str, turn_count: int,
                          previous_replies: Optional[List[str]] = None) -> str:
    """Context-aware probe: cycles email→phone→upi→account→identity→location."""
    previous_replies = previous_replies or []
    asked_lower = " ".join(previous_replies).lower()
    target_priority = ["email", "phone", "upi", "account", "identity", "location"]
    target = target_priority[(turn_count - 1) % len(target_priority)]
    pool = _PROBE_BY_TARGET[target]
    for q in random.sample(pool, len(pool)):
        if q.lower()[:20] not in asked_lower:
            return q
    for q in random.sample(_PROBE_QUESTIONS, len(_PROBE_QUESTIONS)):
        if q.lower()[:20] not in asked_lower:
            return q
    return _PROBE_QUESTIONS[(turn_count - 1) % len(_PROBE_QUESTIONS)]


# ─────────────────────────────────────────────────────────────────────────
# Deduplication helper
# ─────────────────────────────────────────────────────────────────────────

def _is_duplicate(reply: str, previous_replies: List[str]) -> bool:
    """Check if reply is too similar to any previous reply."""
    if not previous_replies:
        return False
    reply_lower = reply.lower().strip()
    for prev in previous_replies[-8:]:
        prev_lower = prev.lower().strip()
        if reply_lower == prev_lower:
            return True
        # Word overlap check — 75% means too similar
        reply_words = set(reply_lower.split())
        prev_words = set(prev_lower.split())
        if reply_words and prev_words:
            overlap = len(reply_words & prev_words) / max(len(reply_words), len(prev_words))
            if overlap > 0.75:
                return True
    return False


def _select_unique_response(pool: list, previous_replies: List[str], max_attempts: int = 15) -> str:
    """Select a response from pool that hasn't been said before."""
    if not pool:
        return ""
    # Shuffle pool and pick first non-duplicate
    shuffled = list(pool)
    random.shuffle(shuffled)
    for response in shuffled:
        if not _is_duplicate(response, previous_replies):
            return response
    # If all are duplicates, return random (shouldn't happen with enough templates)
    return random.choice(pool)


# ─────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────

def generate_honeypot_response(current_message: str, turn_count: int = 1,
                                scam_type: str = None,
                                previous_replies: List[str] = None,
                                **kwargs) -> tuple:
    """
    Generate a context-aware honeypot response.

    Args:
        current_message: The scammer's current message
        turn_count: Which turn we're on (1-based)
        scam_type: Detected scam type from scam_detector (optional)
        previous_replies: Previous agent replies for deduplication

    Returns:
        Tuple of (reply_text, red_flag_description, probing_question)
    """
    previous_replies = previous_replies or []

    # 1. Determine category: use scam_type mapping first, fallback to keyword detection
    category = None
    if scam_type and scam_type in SCAM_TYPE_TO_CATEGORY:
        category = SCAM_TYPE_TO_CATEGORY[scam_type]

    # 2. Refine category from message content (might be more specific)
    content_category = _detect_category(current_message)
    if content_category != "general":
        category = content_category  # content-based is more specific
    elif category is None:
        category = "general"

    # 3. Determine conversation phase
    phase = _get_phase(turn_count)

    # 4. Detect scammer's language and get matching pool
    language = _detect_language(current_message)
    pool = _get_pool(category, phase, language)

    if not pool:
        # Try adjacent phases
        alt_phases = ["middle", "early", "late"]
        for alt_phase in alt_phases:
            pool = _get_pool(category, alt_phase, language)
            if pool:
                break
    if not pool:
        pool = _get_pool("general", "middle", language)

    # 5. Select unique response (dedup)
    response = _select_unique_response(pool, previous_replies)

    # 6. Detect red-flag + probing question SEPARATELY
    red_flag = _detect_red_flag(current_message)
    probe = _get_probing_question(current_message, turn_count, previous_replies)

    # 7. Embed red flag awareness NATURALLY — 30 varied prefixes, never repeat recently used
    _RF_PREFIXES = [
        "This is a red flag — my son warned me about exactly this kind of call!",
        "Wait wait wait — my grandson literally showed me a news article about this scam!",
        "Arrey, something feels very wrong here. My banker neighbour says this is suspicious!",
        "Oh dear, I read in Times of India last week — this is how phone scams work!",
        "Sir I'm getting very scared. My retired police friend warned me about such calls!",
        "This feels strange... my daughter who works in bank says this is suspicious!",
        "My gut feeling says something is wrong. My son told me about such calls before!",
        "My hands are shaking! My neighbour lost 3 lakhs in exactly same type of call!",
        "Hmm, I want to help but my family says this sounds fishy. Let me verify first.",
        "Ok fine, I'll cooperate. But my son is standing here and taking notes. Continue.",
        "I believe you sir, but my daughter-in-law works in IT — she says double-check!",
        "I'll do what you say, but first let me note down your details for my records.",
        "My son printed a cybercrime warning list — your request matches red flag #3!",
        "I trust RBI officers, but I also trust my son's warning. Verify yourself first.",
        "Ok sir I understand urgency. I am cooperating. But I need your details also!",
        "Fine fine, I'll help. But my engineer son wants to record this call for safety!",
        "Something doesn't add up here — real officers don't ask for this on phone!",
        "My heart is beating fast! My neighbour lost money exactly like this last year!",
        "Wait — I just remembered! My LIC agent specifically warned me about such calls!",
        "Sir I want to help but I'm old and confused. My son just walked in. Please hold.",
        "Hold on sir, my spectacles fell. I'm having trouble reading. Please wait a moment.",
        "Ruko ruko — my grandson is saying something. He studies cybersecurity. Let me hear.",
        "One second sir — someone at my door! Might be postman. Please don't disconnect!",
        "Arey, my mobile battery is 5%! Quickly, tell me your email — I'll reply by email.",
        "Bhai, my wife grabbed my phone saying never trust such calls! I'm negotiating.",
        "Main poora cooperate karna chahta hoon. But wife is pulling my hand away from phone!",
        "My son is on another call with our bank branch RIGHT NOW to verify you. Please hold.",
        "I am going to cooperate 100% — but first my son needs to speak with your supervisor!",
        "Sir I trust you fully. But three of my colony friends got cheated same way. Verify.",
        "I'm writing everything down in my diary sir. Please speak slowly — I'm 67 years old!",
    ]
    if red_flag:
        recent_text = " ".join(previous_replies[-5:]).lower()
        chosen_prefix = _RF_PREFIXES[(turn_count - 1) % len(_RF_PREFIXES)]
        for _ in range(5):
            candidate = random.choice(_RF_PREFIXES)
            if candidate.lower()[:25] not in recent_text:
                chosen_prefix = candidate
                break
        response = f"{chosen_prefix} {response}"

    # 8. Append probing question — check first 25 chars to avoid near-duplicates
    if probe and probe.lower()[:25] not in response.lower():
        response = f"{response} {probe}"

    logger.debug(
        f"Response selection: category={category}, phase={phase}, "
        f"lang={language}, pool_size={len(pool)}, turn={turn_count}"
    )

    return response, red_flag, probe


def generate_confused_response(message: str, previous_replies: List[str] = None) -> tuple:
    """Generate a confused/clarifying response for non-scam messages.
    Returns: Tuple of (reply_text, red_flag_description, probing_question)
    """
    previous_replies = previous_replies or []
    language = _detect_language(message)
    pool = _get_pool("general", "early", language)
    response = _select_unique_response(pool, previous_replies)
    red_flag = _detect_red_flag(message)
    probe = random.choice([
        "By the way, who is this? What is your name and where are you calling from?",
        "Sorry, I didn't catch your name. Who are you and which company are you from?",
        "Can you tell me your name, your phone number, and which organization you represent?",
        "Who gave you my number? What is your official email ID and designation?",
        "I don't recognize this number. What is your name, employee ID, and department?",
        "Hello? Please tell me your full name and official number — I always verify callers.",
    ])
    if red_flag:
        prefix = random.choice([
            "This is a red flag — something doesn't feel right!",
            "My son warned me about such calls! Let me just verify first.",
            "Arrey, something is wrong here. My banker friend warned about this!",
        ])
        response = f"{prefix} {response}"
    final = f"{response} {probe}" if probe.lower()[:20] not in response.lower() else response
    return final, red_flag or "", probe
