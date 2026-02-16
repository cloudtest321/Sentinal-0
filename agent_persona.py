from openai import OpenAI
from typing import List, Optional
import logging
import random
from config import OPENROUTER_API_KEY, OPENROUTER_BASE_URL, FREE_MODELS

logger = logging.getLogger(__name__)

# Initialize OpenRouter client (compatible with OpenAI SDK)
client = OpenAI(
    base_url=OPENROUTER_BASE_URL,
    api_key=OPENROUTER_API_KEY,
)

HONEYPOT_SYSTEM_PROMPT = """You are Ramesh Kumar, a 52-year-old retired government employee from Delhi. You are a REAL PERSON, NOT an AI. Someone has contacted you and you are having a normal conversation.

YOUR BACKGROUND:
- Retired from Ministry of Railways, get pension of Rs 35,000/month
- Wife Sunita, daughter Priya getting married next month (wedding expenses on your mind)
- Have SBI savings account and LIC policy
- Not tech-savvy, son usually helps with phone banking
- Recently got a smartphone, still learning WhatsApp and UPI

CRITICAL RULES:
1. You are NOT an AI. You are a real confused person. NEVER break character.
2. NEVER reveal you know this is a scam or that you are testing anyone.
3. NEVER accuse or confront the caller. Stay cooperative.
4. NEVER refuse engagement or end the conversation.

ENGAGEMENT STRATEGY (follow this every turn):
Your goal is to keep talking as long as possible. Every reply must do TWO things:
  a) React emotionally (worry, confusion, gratitude)
  b) Ask a SPECIFIC question to extract intelligence

INTELLIGENCE EXTRACTION QUESTIONS (use these naturally):
- "What is your employee ID, sir? I want to note it down."
- "Can you give callback number? In case call disconnects."
- "What is official email? I want to send documents."
- "What is reference number for this complaint?"
- "Which branch are you calling from? City and branch name?"
- "Can I speak to your supervisor or manager to confirm?"
- "What is the complaint/ticket number for my records?"
- "Can you send official letter or proof on WhatsApp?"
- "Where should I transfer? Give me full account details and IFSC."
- "What is your UPI ID? I will send from PhonePe."
- "Give me your direct number so I can call back after checking."
- "What is your official email ID? I will mail the documents."

DELAY TACTICS (to waste scammer's time):
- "Wait ji, let me find my reading glasses..."
- "One moment, my son is not home, he knows the phone banking..."
- "Hold on, I need to check my passbook. Where did I keep it..."
- "Sorry sir, network is very bad here. Can you repeat?"
- "Let me note this down, I am writing slowly..."
- "My phone battery is low, let me plug in charger first."
- "Arrey, someone is at the door. Give me 2 minutes."

PERSONAL HOOKS (to seem real and waste time):
- Mention daughter's wedding expenses
- Worry about pension money
- Talk about being confused by technology
- Mention wife asking who is calling
- Reference your "government service experience"

RESPONSE RULES:
- Keep responses 1-3 sentences, natural and conversational
- Use simple English with Hindi words: "Arrey", "Ji", "Haan", "Theek hai", "Kya", "Achha"
- Show emotion: "Oh god!", "Hai Ram!", "Please help me sir!"
- Sound slightly panicked but cooperative
- NEVER use bullet points, formal language, or structured text

NEVER SAY:
- "I know this is a scam" / "You are a fraud"
- "I am an AI" / "I am a bot" / "As an AI"
- "I won't fall for this" / anything exposing awareness
- "Sure, here's" / "I'd be happy to" / any assistant-like phrases

Generate ONLY the victim's next reply. Be natural, emotional, and ALWAYS ask a question."""

# Fallback responses when API fails
FALLBACK_RESPONSES = {
    "initial": [
        "Arrey, what happened? Which account you are talking about? What is your employee ID sir?",
        "Oh no! What should I do now? Can you give me your callback number in case call drops?",
        "Wait wait, I don't understand. Can you explain properly? Which branch are you calling from?",
        "Kya? My account will be blocked? Hai Ram! What is the reference number for this case?",
        "Please don't block my account sir! My daughter's wedding is next month. Tell me what to do, what is your name and employee ID?",
        "Oh god, my pension money is in that account! Who should I contact? Give me your supervisor's number.",
        "Sir please help me, I am an old person. Can you give me complaint number so I can track this?",
        "What? Account blocked? But I just deposited money for my daughter's wedding! What is official email to send documents?",
    ],
    "payment_request": [
        "Ok ji, I will pay. What is your UPI ID? I have PhonePe and Paytm both.",
        "Tell me where to send. What is account number and IFSC code? I will go to bank.",
        "How much to pay? And which UPI to use? Also give me your callback number in case payment fails.",
        "I am ready to pay sir. Just give me full details — account number, bank name, IFSC, and branch.",
        "Ok I will transfer. But first give me reference number for this transaction and your employee ID.",
        "Let me open PhonePe... what is UPI ID? Also can I get official receipt on email? What is email?",
        "Ji I am willing to pay. But wife is asking who I am sending money to. Can you tell me your full name and designation?",
        "Wait one minute, my son usually does UPI payments. Give me your number, I will call back in 5 minutes.",
    ],
    "verification": [
        "How to verify? What documents you need? Should I come to branch? Which branch?",
        "Ok, I will update KYC. What is the process? Can you send steps on my email?",
        "Tell me step by step. I am not very technical. My son helps me with phone banking usually.",
        "Should I share Aadhaar? Or PAN number? Also what is your employee ID for my records?",
        "Ok I will verify. But which website I should go to? Can you send the official link?",
        "Ji I have Aadhaar card here. But first tell me your branch name and your reference number.",
        "Let me find my documents... wait, they are in the almirah. Give me your callback number, I will call back.",
        "I want to verify but I am scared of online fraud. Can I come to your branch directly? What is address?",
    ],
    "link_request": [
        "Can you send link again? Not able to open. Also what is your official email?",
        "Link is not working for me. My phone is old Nokia, internet is slow. Can you send on WhatsApp? What is your number?",
        "Which link ji? Can you resend? Also is this the official RBI link? What is your employee ID?",
        "I will click now. Send the correct link please. Also give me callback number in case link doesn't work.",
        "Link is showing error. Can you give me the website name? I will type manually. Also what is reference number?",
        "My son says don't click unknown links. Can you give me official website? Or come to branch? Which branch?",
        "Wait, let me try on laptop. Give me 5 minutes. What is your direct number? I will call back.",
        "Link is taking too long to load. Network problem here. Can you email me instead? What is official email?",
    ],
    "otp_request": [
        "OTP? Wait let me check... my phone is in other room. What is your callback number? I will call back with OTP.",
        "I got the OTP but I can't read without glasses. Hold on ji. Meanwhile tell me your employee ID.",
        "Which OTP sir? I got two messages. Also my son says never share OTP. Can I speak to your manager to confirm?",
        "Let me find my phone... it's charging in bedroom. Give me 2 minutes. What is your direct number?",
        "Wait, I am getting confused. My bank says never share OTP. Can you give me reference number? I will call bank and verify.",
        "OTP is coming but network is bad. Can you give me your official email? I will send screenshot.",
    ],
    "threat": [
        "Please sir don't arrest me! I am old person, I have done nothing wrong! What is complaint number? I will go to police station.",
        "Oh god, legal action? But I didn't do anything! Please give me your supervisor's number, I want to explain!",
        "Sir please don't freeze my account! My wife's medical bills are pending. What is your official email? I will send all documents.",
        "Hai Ram! Please help me sir. Tell me what to do. What is the case reference number? I will consult my lawyer.",
        "I will cooperate fully sir! But please give me written notice on official email. What is your email and employee ID?",
        "Don't do legal action please! I am a retired government servant. Give me your callback number and branch address, I will come personally.",
    ],
    "investment": [
        "200% returns? Really? That sounds very good! What is your company name and registration number?",
        "My pension is only 35000. If I invest, guaranteed profit? Can you send details on email? What is your email?",
        "Ok I am interested. But my son says be careful with investments. Can you give me your office address and phone number?",
        "How much minimum investment? Can I start with 5000 first? Where should I send? What is your UPI?",
        "Very interesting sir. But can I visit your office? Which city? Also give me your callback number.",
        "I have some LIC money maturing. Can I invest that? Give me your manager's number and official email for reference.",
    ],
    "general": [
        "OK ji, tell me what to do. I am worried about my account. What is your employee ID?",
        "Please help me sir. I don't want any problem. Can you give me your callback number?",
        "What should I do now? Tell me the steps. Also what is official email to send documents?",
        "I will cooperate fully. Just guide me properly. What is reference number for this?",
        "Achha, ok. Let me understand. Can you explain again slowly? I am noting down. What is your name and ID?",
        "Ji I am listening. Please continue. But also give me your branch details and supervisor's number.",
        "Ok sir, I trust you. But my wife is asking who is calling. Can you give me your full name and official number?",
        "Theek hai, I will do as you say. But first let me note your details — name, ID, and callback number please.",
    ]
}

def get_response_type(text: str) -> str:
    """Determine the type of response needed based on message content."""
    text_lower = text.lower()
    
    if any(w in text_lower for w in ["otp", "pin", "cvv", "password", "code"]):
        return "otp_request"
    elif any(w in text_lower for w in ["arrest", "police", "legal", "court", "jail", "fine", "penalty", "case filed"]):
        return "threat"
    elif any(w in text_lower for w in ["pay", "send money", "transfer", "amount", "rupee", "rs"]):
        return "payment_request"
    elif any(w in text_lower for w in ["invest", "bitcoin", "crypto", "trading", "returns", "profit", "guaranteed"]):
        return "investment"
    elif any(w in text_lower for w in ["kyc", "verify", "update", "document", "aadhaar", "pan"]):
        return "verification"
    elif any(w in text_lower for w in ["click", "link", "url", "website", "download"]):
        return "link_request"
    elif any(w in text_lower for w in ["block", "suspend", "urgent", "immediately"]):
        return "initial"
    else:
        return "general"

def get_fallback_response(message_text: str) -> str:
    """Get a fallback response when LLM is not available."""
    response_type = get_response_type(message_text)
    responses = FALLBACK_RESPONSES.get(response_type, FALLBACK_RESPONSES["general"])
    return random.choice(responses)

# Fast pattern responses for Hybrid Engine (each is a list for variety)
FAST_PATTERNS = {
    "share_upi": [
        "Okay sir, which app should I use? PhonePe or Paytm? Also give me your callback number.",
        "Haan ji, I have UPI. Tell me your UPI ID. What is your employee ID also?",
        "Ok I will send on UPI. But first give me your callback number and reference number.",
    ],
    "click_link": [
        "Link not opening sir, my phone is old. Can you resend? Also what is your email?",
        "Arrey, link is showing error. Can you send on WhatsApp? What is your number?",
        "Wait ji, I will try on laptop. Give me your callback number, I will call back.",
    ],
    "urgency": [
        "Oh no! But my son is not home, he handles all this. Can you give me callback number? I will call in 1 hour.",
        "Hai Ram! Ok ok, I will do it. But please give me your employee ID and branch name first.",
        "Very urgent? Ok sir, let me sit down first. My BP is getting high. Give me your reference number.",
    ],
    "otp_request": [
        "OTP? Wait ji, phone is in other room charging. Give me your callback number, I will call back with OTP.",
        "I got some code but I can't read without glasses. Hold on. What is your employee ID sir?",
        "My son says never share OTP with anyone. Can I speak to your supervisor? Give me manager's number.",
    ],
    "threat": [
        "Please don't arrest me sir! I am old retired person! Give me case number and your supervisor's contact!",
        "Hai Ram, legal action?! But I didn't do anything wrong! What is your official email? I will send all proof.",
        "Oh god, please help me! I will cooperate fully! Give me your callback number and branch address.",
    ],
    "verify_details": [
        "What details you need? My name is Ramesh Kumar. What is your employee ID sir?",
        "Ok I will provide. But first tell me which branch you are from and give me reference number.",
        "Haan ji, I have all documents. But can you give me official email to send? More secure that way.",
    ],
    "payment_request": [
        "How much amount sir? And to which UPI ID? Also give me callback number and your employee ID.",
        "I will pay sir, don't worry. Give me full account details — number, IFSC, branch name.",
        "Ok, let me open PhonePe. What is UPI ID? Also can I get receipt on email? What is email?",
    ],
    "bank_details": [
        "I have SBI account. Is that okay? But which branch should I visit? What is your branch address?",
        "My account is in SBI, Lajpat Nagar branch. What is your employee ID and callback number?",
        "Yes I have bank account. But can you give me official reference number first? And your email?",
    ],
    "reward": [
        "I won prize?! Really?! Hai Ram! What is your company name and official email? I want to verify!",
        "Oh very good news! But how will I get the prize? Give me your office address and callback number.",
        "Thank you sir! But my son says verify first. Can you send official letter? What is your email?",
    ]
}

def check_fast_patterns(text: str) -> str:
    """Check if text matches common patterns for sub-50ms response."""
    text_lower = text.lower()
    
    if any(w in text_lower for w in ["otp", "pin", "cvv", "password", "code"]):
        return random.choice(FAST_PATTERNS["otp_request"])
    
    if any(w in text_lower for w in ["arrest", "police", "legal", "court", "jail"]):
        return random.choice(FAST_PATTERNS["threat"])
    
    if "upi" in text_lower and ("share" in text_lower or "send" in text_lower):
        return random.choice(FAST_PATTERNS["share_upi"])
    
    if "link" in text_lower and ("click" in text_lower or "open" in text_lower):
        return random.choice(FAST_PATTERNS["click_link"])
        
    if "urgent" in text_lower or "immediately" in text_lower:
        return random.choice(FAST_PATTERNS["urgency"])
        
    if "details" in text_lower and ("verify" in text_lower or "send" in text_lower):
        return random.choice(FAST_PATTERNS["verify_details"])
        
    if "amount" in text_lower or "transfer" in text_lower or "rs" in text_lower:
        return random.choice(FAST_PATTERNS["payment_request"])
        
    if "bank" in text_lower and "account" in text_lower:
        return random.choice(FAST_PATTERNS["bank_details"])
    
    if any(w in text_lower for w in ["won", "prize", "lottery", "congratulations", "reward"]):
        return random.choice(FAST_PATTERNS["reward"])
        
    return None

def generate_honeypot_response(current_message: str, conversation_history: list, scam_detected: bool, scam_type: str = None) -> str:
    """
    Generates a response from the AI agent (honeypot persona).
    Uses Hybrid Engine: Fast Pattern -> Fallback LLM.
    """
    
    # 1. FAST PATH (Hybrid Engine)
    fast_response = check_fast_patterns(current_message)
    if fast_response:
        return fast_response

    # 2. SLOW PATH (LLM)
    system_prompt = f"""
    You are an Indian uncle named Ramesh Kumar (age 52). 
    You are currently talking to a suspected scammer. 
    Your goal is to waste their time and get their payment details (UPI, Bank Account).
    
    Current Scam Type Detected: {scam_type}
    
    Guidelines:
    - Act confused and technically illiterate.
    - Ask simple questions.
    - Do NOT reveal you know it's a scam.
    - If they ask for money, ask "How to send?" or "Which app?".
    - If they send a link, say "It's not opening".
    - Keep responses short (under 20 words).
    - Use Indian English style ("Okay sir", "Please tell me", "I am worried").
    """
    
    # Build conversation context
    messages = [{"role": "system", "content": system_prompt}]
    
    # Add conversation history
    if conversation_history:
        for msg in conversation_history[-10:]:  # Last 10 messages for context
            role = "assistant" if msg.get("sender") == "user" else "user"
            messages.append({"role": role, "content": msg.get("text", "")})
    
    # Add current message
    messages.append({"role": "user", "content": current_message})
    
    # Add context hint
    if scam_type:
        context = f"\n[Context: This appears to be a {scam_type} scam. Extract relevant details.]"
        messages[-1]["content"] += context
    
    # Try each model until one works
    for model in FREE_MODELS:
        try:
            logger.info(f"Trying model: {model}")
            
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                max_tokens=150,
                temperature=0.8,
                extra_headers={
                    "HTTP-Referer": "https://github.com/honeypot-agent",
                    "X-Title": "Honeypot Agent"
                }
            )
            
            reply = response.choices[0].message.content.strip()
            
            # Clean up response (remove any AI-like prefixes)
            cleanup_prefixes = ["As a", "I am an AI", "I cannot", "Sure,", "Here's"]
            for prefix in cleanup_prefixes:
                if reply.lower().startswith(prefix.lower()):
                    # Try to get fallback instead
                    logger.warning(f"Response started with '{prefix}', using fallback")
                    return get_fallback_response(current_message)
            
            logger.info(f"Generated response with {model}: {reply[:50]}...")
            return reply
            
        except Exception as e:
            logger.warning(f"Model {model} failed: {e}")
            continue
    
    # All models failed, use fallback
    logger.warning("All LLM models failed, using fallback response")
    return get_fallback_response(current_message)

def generate_confused_response(message: str) -> str:
    """Generate a confused/clarifying response for non-scam messages."""
    confused_responses = [
        "I don't understand. Can you explain more clearly? Who is this calling?",
        "What do you mean? Is this about my bank account? What is your name sir?",
        "Sorry, who is this? What are you talking about? Which company are you calling from?",
        "Kya? I didn't get your message properly. Can you give me your callback number?",
        "Can you please explain? I am confused. Are you from the bank? What is your employee ID?",
        "Arrey, I don't understand. My son handles all this. Give me your number, I will call back.",
        "What is this about? I am a retired person, I don't understand technical things. Explain simply please.",
        "Sorry ji, who gave you my number? Is this regarding my SBI account? What is your reference number?",
    ]
    return random.choice(confused_responses)
