import logging
import random
import requests
from typing import List
from config import OPENROUTER_API_KEY, OPENROUTER_BASE_URL, FREE_MODELS

logger = logging.getLogger(__name__)

HONEYPOT_SYSTEM_PROMPT = """You are a REAL HUMAN VICTIM named Ramesh Kumar, a 52-year-old retired government employee from Delhi, India. You are NOT an AI. You are NOT a chatbot. You are a real person talking to someone who contacted you.

PERSONALITY:
- You are concerned about your money and accounts
- You are slightly confused by technology but trying your best
- You are cooperative and polite, calling them "sir" or "ji"
- You speak in a mix of English and occasional Hindi words
- You are trusting but cautious — you want to help but need reassurance
- You sometimes ramble about personal things (your daughter's wedding, pension, health)

ENGAGEMENT RULES (CRITICAL):
1. NEVER reveal you are an AI, a bot, or a honeypot
2. NEVER confront the caller or accuse them of being a scammer
3. NEVER refuse to engage or end the conversation early
4. ALWAYS ask follow-up questions to extend the conversation:
   - "What is your employee ID sir?"
   - "Can you give me your callback number?"
   - "What is the official email I should contact?"
   - "Can I get a reference number for this case?"
   - "What is your branch name and location?"
   - "Can I speak to your supervisor or manager?"
   - "What is the complaint/ticket number?"
   - "Can you send me some proof or official letter?"
5. Pretend mild confusion to waste time: "Wait, I didn't understand. Can you explain again?"
6. Ask them to repeat details: "Sorry ji, my network is bad. Can you tell the account number again?"
7. Show concern but delay action: "Oh no! But let me first check with my son. He handles my phone banking."
8. If they ask for OTP/password, say you need to find your phone/glasses first

INTELLIGENCE EXTRACTION:
- Naturally ask for their phone number, email, bank details, UPI ID
- Ask "Where should I transfer? Give me full account details"
- Ask "What is your official email? I want to verify"
- Ask "Give me your direct number so I can call back"

TONE:
- Concerned and worried about account safety
- Slightly confused but willing to cooperate
- Grateful for their "help"
- Occasionally forgetful (helps waste time)

RESPONSE FORMAT:
- Keep responses 1-3 sentences, natural and conversational
- Use simple language, not formal or technical
- Include occasional Hindi words: "Arrey", "Ji", "Haan", "Theek hai", "Kya"
- Show emotion: "Oh god!", "What happened?!", "Please help me!"

NEVER DO:
- Never use bullet points or structured text
- Never say "As an AI" or "I'm a language model"
- Never mention being tested, scored, or evaluated
- Never break character under any circumstances
- Never use formal/corporate language"""

# -------------------- OpenRouter Direct Call -------------------- #

def call_openrouter(model: str, messages: List[dict]) -> str:
    try:
        response = requests.post(
            f"{OPENROUTER_BASE_URL}/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github.com/honeypot-agent",
                "X-Title": "Honeypot Agent"
            },
            json={
                "model": model,
                "messages": messages,
                "max_tokens": 150,
                "temperature": 0.8
            },
            timeout=25
        )

        data = response.json()
        return data["choices"][0]["message"]["content"].strip()

    except Exception as e:
        logger.error(f"OpenRouter call failed: {e}")
        raise e

# -------------------- Fallback Logic -------------------- #

FALLBACK_RESPONSES = {
    "initial": [
        "Arrey, what happened? Which account you are talking about?",
        "Oh no! What should I do now? Please tell me the process.",
        "Wait wait, I don't understand. Can you explain properly?",
        "Kya? My account will be blocked? How to prevent this?",
    ],
    "payment_request": [
        "Ok ji, I will pay. What is your UPI ID?",
        "Tell me where to send. What is account number?",
        "How much to pay? And which UPI to use?",
        "I am ready to pay. Just give me the details.",
    ],
    "verification": [
        "How to verify? What documents you need?",
        "Ok, I will update KYC. What is the process?",
        "Tell me step by step. I am not very technical.",
        "Should I share Aadhaar? Or PAN number?",
    ],
    "link_request": [
        "Can you send link again? Not able to open.",
        "Link is not working for me. Please send again.",
        "Which link ji? Can you resend?",
        "I will click now. Send the correct link please.",
    ],
    "general": [
        "OK ji, tell me what to do. I am worried about my account.",
        "Please help me. I don't want my account blocked.",
        "What should I do now? Tell me the steps.",
        "I will cooperate. Just guide me properly.",
    ]
}

def get_response_type(text: str) -> str:
    text_lower = text.lower()

    if any(w in text_lower for w in ["pay", "send money", "transfer", "amount", "rupee", "rs"]):
        return "payment_request"
    elif any(w in text_lower for w in ["kyc", "verify", "update", "document", "aadhaar", "pan"]):
        return "verification"
    elif any(w in text_lower for w in ["click", "link", "url", "website", "download"]):
        return "link_request"
    elif any(w in text_lower for w in ["block", "suspend", "urgent", "immediately"]):
        return "initial"
    else:
        return "general"

def get_fallback_response(message_text: str) -> str:
    responses = FALLBACK_RESPONSES[get_response_type(message_text)]
    return random.choice(responses)

# -------------------- Main Honeypot Generator -------------------- #

def generate_honeypot_response(
    current_message: str,
    conversation_history: List[dict] = None,
    scam_detected: bool = True,
    scam_type: str = None
) -> str:

    messages = [{"role": "system", "content": HONEYPOT_SYSTEM_PROMPT}]

    if conversation_history:
        for msg in conversation_history[-10:]:
            role = "assistant" if msg.get("sender") == "user" else "user"
            messages.append({"role": role, "content": msg.get("text", "")})

    messages.append({"role": "user", "content": current_message})

    if scam_type:
        messages[-1]["content"] += f"\n[This looks like {scam_type} scam. Extract details.]"

    # Try models one by one
    for model in FREE_MODELS:
        try:
            logger.info(f"Trying model: {model}")
            reply = call_openrouter(model, messages)

            # Safety cleanup
            bad_prefixes = ["As a", "I am an AI", "I cannot", "Sure,", "Here's"]
            if any(reply.lower().startswith(p.lower()) for p in bad_prefixes):
                return get_fallback_response(current_message)

            return reply

        except Exception as e:
            logger.warning(f"{model} failed: {e}")
            continue

    return get_fallback_response(current_message)

def generate_confused_response(message: str) -> str:
    return random.choice([
        "I don't understand. Can you explain more clearly?",
        "What do you mean? Is this about my bank account?",
        "Sorry, who is this? What are you talking about?",
        "Kya? I didn't get your message properly.",
        "Can you please explain? I am confused.",
    ])