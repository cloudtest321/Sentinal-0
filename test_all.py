"""
Honeypot Agent — Comprehensive Automated Test Suite
Tests all modules: scam_detector, intelligence, agent_persona, scammer_dna,
session_manager, engagement_metrics, models, and full API integration.
Run with: python test_all.py
"""
import sys
import os
import time
import json
import traceback

# ─────────────────────────────────────────────
# Test Framework
# ─────────────────────────────────────────────
results = []
current_module = ""

def set_module(name):
    global current_module
    current_module = name
    print(f"\n{'='*60}")
    print(f"  MODULE: {name}")
    print(f"{'='*60}")

def test(name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    icon = "✅" if condition else "❌"
    results.append({"module": current_module, "test": name, "status": status, "detail": detail})
    print(f"  {icon} {name}" + (f" — {detail}" if detail and not condition else ""))

# ─────────────────────────────────────────────
# MODULE 1: Scam Detector
# ─────────────────────────────────────────────
def test_scam_detector():
    set_module("scam_detector")
    from scam_detector import detect_scam, get_scam_type

    # Test 1: Clear scam message
    detected, kws = detect_scam("Your account is blocked. Call immediately to verify KYC.")
    test("Detects obvious scam message", detected, f"score triggered, keywords={kws}")

    # Test 2: Benign message
    detected2, kws2 = detect_scam("Hey, want to grab coffee tomorrow?")
    test("Benign message not flagged", not detected2, f"keywords={kws2}")

    # Test 3: Financial keywords alone shouldn't trigger (need score < 3)
    detected3, kws3 = detect_scam("I went to the bank yesterday.")
    test("Single financial keyword below threshold", not detected3, f"keywords={kws3}")

    # Test 4: URL detection
    detected4, kws4 = detect_scam("Click this link https://fake-bank.com to update your account urgently")
    test("URL + urgency detected as scam", detected4, f"keywords={kws4}")
    test("contains_url keyword present", "contains_url" in kws4)

    # Test 5: UPI detection
    detected5, kws5 = detect_scam("Send money to fraud@paytm immediately")
    test("UPI pattern detected as scam", detected5, f"keywords={kws5}")
    test("contains_upi keyword present", "contains_upi" in kws5)

    # Test 6: Phone number detection
    detected6, kws6 = detect_scam("Your account will be blocked. Call 9876543210 now.")
    test("Phone number detected in scam", detected6)
    test("contains_phone keyword present", "contains_phone" in kws6)

    # Test 7: Conversation history boosts scoring
    history = [
        {"text": "Your bank account needs verification"},
        {"text": "Please send your account details"}
    ]
    detected7, kws7 = detect_scam("Please update now", history)
    test("Conversation history boosts scam score", detected7, f"keywords={kws7}")

    # Test 8: Scam type classification
    test("KYC_FRAUD type detected", get_scam_type(["kyc", "verify"]) == "KYC_FRAUD")
    test("LOTTERY_SCAM type detected", get_scam_type(["won", "prize"]) == "LOTTERY_SCAM")
    test("ACCOUNT_THREAT type detected", get_scam_type(["blocked", "suspended"]) == "ACCOUNT_THREAT")
    test("OTP_FRAUD type detected", get_scam_type(["otp", "pin"]) == "OTP_FRAUD")
    test("PHISHING type detected", get_scam_type(["contains_url"]) == "PHISHING")
    test("GENERAL_FRAUD fallback", get_scam_type(["random"]) == "GENERAL_FRAUD")

    # Test 9: Threat keywords highest weight
    detected9, _ = detect_scam("Your account is blocked")  # blocked=+3, account=+1 = 4 >= 3
    test("Threat keyword (blocked) alone triggers scam", detected9)

    # Test 10: Reward scam
    detected10, kws10 = detect_scam("Congratulations! You won a lottery prize of 50000 rupees!")
    test("Reward/lottery scam detected", detected10)

    # Test 11: Investment scam
    detected11, kws11 = detect_scam("Invest in bitcoin today for guaranteed returns of 200% profit!")
    test("Investment/crypto scam detected", detected11)
    test("INVESTMENT_SCAM type detected", get_scam_type(kws11) == "INVESTMENT_SCAM")

    # Test 12: Job scam
    detected12, kws12 = detect_scam("Job offer: work from home and earn salary of 50000 per month! Hiring now.")
    test("Job scam detected", detected12)
    test("JOB_SCAM type detected", get_scam_type(kws12) == "JOB_SCAM")

# ─────────────────────────────────────────────
# MODULE 2: Intelligence Extractor
# ─────────────────────────────────────────────
def test_intelligence():
    set_module("intelligence")
    from intelligence import (extract_bank_accounts, extract_upi_ids,
                              extract_phishing_links, extract_phone_numbers,
                              extract_suspicious_keywords, extract_all_intelligence,
                              extract_from_conversation, extract_email_addresses)
    from models import ExtractedIntelligence

    # Bank accounts
    banks = extract_bank_accounts("Transfer to account 12345678901234 immediately")
    test("Extracts 14-digit bank account", "12345678901234" in banks, f"found={banks}")

    # Phone number NOT treated as bank account
    banks2 = extract_bank_accounts("Call 9876543210 for help")
    test("10-digit phone NOT extracted as bank account", "9876543210" not in banks2, f"found={banks2}")

    # UPI IDs
    upis = extract_upi_ids("Pay to fraud@paytm or scammer@ybl for verification")
    test("Extracts UPI ID fraud@paytm", "fraud@paytm" in upis, f"found={upis}")
    test("Extracts UPI ID scammer@ybl", "scammer@ybl" in upis, f"found={upis}")

    # Phishing links
    links = extract_phishing_links("Click https://fake-bank.com/verify or www.scam-site.org")
    test("Extracts https URL", any("fake-bank.com" in l for l in links), f"found={links}")
    test("Extracts www URL", any("scam-site" in l for l in links), f"found={links}")

    # Phone numbers
    phones = extract_phone_numbers("Call +919876543210 or 8765432109")
    test("Extracts +91 phone number", "+919876543210" in phones, f"found={phones}")
    test("Extracts 10-digit phone (auto +91 prefix)", "+918765432109" in phones, f"found={phones}")

    # 91-prefix phone normalization
    phones2 = extract_phone_numbers("Call 919876543210")
    test("Normalizes 91-prefix to +91", "+919876543210" in phones2, f"found={phones2}")

    # Suspicious keywords
    kws = extract_suspicious_keywords("Urgent! Your account is blocked. Verify KYC immediately with OTP.")
    test("Extracts 'urgent' keyword", "urgent" in kws)
    test("Extracts 'blocked' keyword", "blocked" in kws)
    test("Extracts 'kyc' keyword", "kyc" in kws)
    test("Extracts 'otp' keyword", "otp" in kws)

    # Full extraction
    intel = extract_all_intelligence(
        "Send ₹5000 to UPI fraud@upi. Bank acc 123456789012. Call +919999888877. Visit https://scam.com"
    )
    test("Full extraction finds bank account", len(intel.bankAccounts) > 0)
    test("Full extraction finds UPI", "fraud@upi" in intel.upiIds)
    test("Full extraction finds phone", "+919999888877" in intel.phoneNumbers)
    test("Full extraction finds URL", any("scam.com" in l for l in intel.phishingLinks))

    # Merge with existing
    existing = ExtractedIntelligence(upiIds=["old@paytm"], phoneNumbers=["+911111111111"])
    merged = extract_all_intelligence("New UPI: new@upi", existing)
    test("Merge preserves existing UPI", "old@paytm" in merged.upiIds)
    test("Merge adds new UPI", "new@upi" in merged.upiIds)
    test("Merge preserves existing phone", "+911111111111" in merged.phoneNumbers)

    # Conversation extraction
    msgs = [
        {"text": "Send to fraud@paytm"},
        {"text": "Call +919876543210"},
        {"text": "Bank account 12345678901234"}
    ]
    conv_intel = extract_from_conversation(msgs)
    test("Conversation extraction finds UPI", "fraud@paytm" in conv_intel.upiIds)
    test("Conversation extraction finds phone", "+919876543210" in conv_intel.phoneNumbers)
    test("Conversation extraction finds bank", "12345678901234" in conv_intel.bankAccounts)

    # Deduplication
    intel_dup = extract_all_intelligence("fraud@paytm fraud@paytm fraud@paytm")
    test("Deduplicates UPI IDs", intel_dup.upiIds.count("fraud@paytm") == 1)

    # Email extraction
    emails = extract_email_addresses("Contact us at scammer@gmail.com or support@fake-bank.org")
    test("Extracts email scammer@gmail.com", "scammer@gmail.com" in emails, f"found={emails}")
    test("Extracts email support@fake-bank.org", "support@fake-bank.org" in emails, f"found={emails}")

    # Email NOT confused with UPI
    emails2 = extract_email_addresses("Send to fraud@paytm or user@ybl")
    test("UPI IDs filtered from email extraction", "fraud@paytm" not in emails2, f"found={emails2}")

    # Email in full extraction
    intel_email = extract_all_intelligence("Contact admin@scamsite.com for help")
    test("Full extraction finds email", "admin@scamsite.com" in intel_email.emailAddresses, f"found={intel_email.emailAddresses}")

    # Email merge
    existing_email = ExtractedIntelligence(emailAddresses=["old@test.com"])
    merged_email = extract_all_intelligence("Contact new@fraud.com", existing_email)
    test("Email merge preserves existing", "old@test.com" in merged_email.emailAddresses)
    test("Email merge adds new", "new@fraud.com" in merged_email.emailAddresses)

# ─────────────────────────────────────────────
# MODULE 3: Agent Persona
# ─────────────────────────────────────────────
def test_agent_persona():
    set_module("agent_persona")
    from agent_persona import get_response_type, get_fallback_response, FALLBACK_RESPONSES

    # Response type classification
    test("Payment request classified", get_response_type("Please pay ₹5000 now") == "payment_request")
    test("Verification classified", get_response_type("Update your KYC documents") == "verification")
    test("Link request classified", get_response_type("Click this link to download app") == "link_request")
    test("Initial threat classified", get_response_type("Your account is blocked immediately") == "initial")
    test("General fallback", get_response_type("Hello how are you") == "general")

    # Fallback responses exist for all types
    for rtype in ["initial", "payment_request", "verification", "link_request", "general"]:
        test(f"Fallback responses exist for '{rtype}'", len(FALLBACK_RESPONSES[rtype]) > 0)

    # Fallback response returns string
    resp = get_fallback_response("Send money to this UPI")
    test("Fallback response is non-empty string", isinstance(resp, str) and len(resp) > 0, f"resp={resp}")

    # Multiple calls return (potentially different) responses — all valid
    responses = set()
    for _ in range(20):
        r = get_fallback_response("Pay ₹5000")
        responses.add(r)
    test("Fallback has response variety (randomized)", len(responses) >= 2, f"unique={len(responses)}")

# ─────────────────────────────────────────────
# MODULE 4: ScammerDNA
# ─────────────────────────────────────────────
def test_scammer_dna():
    set_module("scammer_dna")
    from scammer_dna import ScammerDNA

    dna = ScammerDNA()

    # Basic fingerprint generation
    history = [
        {"sender": "scammer", "text": "Your account is blocked urgently", "timestamp": 1000000},
        {"sender": "user", "text": "Oh no what happened?", "timestamp": 1005000},
        {"sender": "scammer", "text": "Send money to verify immediately", "timestamp": 1008000},
    ]
    sig, features = dna.generate_fingerprint_from_history(history)
    test("Generates 12-char signature", len(sig) == 12, f"sig={sig}")
    test("Features has 'keywords' key", "keywords" in features)
    test("Features has 'timing' key", "timing" in features)
    test("Features has 'structure' key", "structure" in features)
    test("Features has 'tactics' key", "tactics" in features)

    # Same input → same signature (deterministic)
    sig2, _ = dna.generate_fingerprint_from_history(history)
    test("Same input produces same signature", sig == sig2)

    # Different input → different signature
    history2 = [
        {"sender": "scammer", "text": "Congratulations you won lottery prize!", "timestamp": 2000000},
        {"sender": "user", "text": "Really?", "timestamp": 2003000},
    ]
    sig3, _ = dna.generate_fingerprint_from_history(history2)
    test("Different input produces different signature", sig != sig3, f"sig1={sig}, sig3={sig3}")

    # Timing analysis
    test("Timing pattern is string", isinstance(features["timing"], str))
    test("Timing pattern is valid value",
         features["timing"] in ["automated_fast", "human_responsive", "human_slow", "insufficient_data", "no_pattern"])

    # Structure analysis
    test("Structure is valid value",
         features["structure"] in ["short_bursts", "long_scripts", "balanced", "unknown"])

    # Tactics detection
    test("Tactics is a list", isinstance(features["tactics"], list))
    test("Urgency tactic detected", "urgency" in features["tactics"])

    # Edge case: empty history
    sig_empty, feat_empty = dna.generate_fingerprint_from_history([])
    test("Handles empty history", len(sig_empty) == 12)

    # Edge case: single message
    sig_single, feat_single = dna.generate_fingerprint_from_history(
        [{"sender": "scammer", "text": "Hello", "timestamp": 1000}]
    )
    test("Handles single message", len(sig_single) == 12)
    test("Single message timing is insufficient", feat_single["timing"] == "insufficient_data")

# ─────────────────────────────────────────────
# MODULE 5: Session Manager
# ─────────────────────────────────────────────
def test_session_manager():
    set_module("session_manager")
    from session_manager import SessionManager, SessionData
    from models import ExtractedIntelligence

    # Create fresh manager for testing
    # Reset singleton
    SessionManager._instance = None
    sm = SessionManager()

    # Create session
    s1 = sm.get_or_create_session("test-sess-1")
    test("Creates new session", isinstance(s1, SessionData))
    test("Session ID matches", s1.session_id == "test-sess-1")
    test("Scam not detected initially", s1.scam_detected == False)
    test("Message count starts at 0", s1.message_count == 0)
    test("Callback not sent initially", s1.callback_sent == False)

    # Get existing session
    s1_again = sm.get_or_create_session("test-sess-1")
    test("Returns existing session on same ID", s1 is s1_again)

    # Update session
    intel = ExtractedIntelligence(upiIds=["fraud@upi"], phoneNumbers=["+919999999999"])
    s1_updated = sm.update_session("test-sess-1", scam_detected=True, intelligence=intel,
                                   scam_type="KYC_FRAUD", increment_messages=True)
    test("Scam detected after update", s1_updated.scam_detected == True)
    test("Message count incremented", s1_updated.message_count == 1)
    test("Scam type set", s1_updated.scam_type == "KYC_FRAUD")
    test("UPI intelligence stored", "fraud@upi" in s1_updated.intelligence.upiIds)

    # Cumulative intelligence merge
    intel2 = ExtractedIntelligence(bankAccounts=["123456789012"])
    sm.update_session("test-sess-1", intelligence=intel2, increment_messages=True)
    test("Bank account merged", "123456789012" in s1.intelligence.bankAccounts)
    test("Previous UPI preserved after merge", "fraud@upi" in s1.intelligence.upiIds)
    test("Message count is now 2", s1.message_count == 2)

    # Agent notes
    s1.add_note("Test note 1")
    s1.add_note("Test note 2")
    test("Agent notes stored", len(s1.agent_notes) == 2)
    test("Notes string formatted", "Test note 1 | Test note 2" == s1.get_notes_string())

    # Mark callback
    sm.mark_callback_sent("test-sess-1")
    test("Callback marked as sent", s1.callback_sent == True)

    # Should trigger early callback
    should_trigger = sm.should_trigger_early_callback("test-sess-1")
    test("Should trigger callback (has intel + scam detected)", should_trigger)

    # Non-existent session
    s_none = sm.get_session("nonexistent")
    test("Returns None for nonexistent session", s_none is None)
    test("Should not trigger for nonexistent", not sm.should_trigger_early_callback("nonexistent"))

    # Clear session
    sm.clear_session("test-sess-1")
    test("Session cleared", sm.get_session("test-sess-1") is None)

# ─────────────────────────────────────────────
# MODULE 6: Engagement Metrics
# ─────────────────────────────────────────────
def test_engagement_metrics():
    set_module("engagement_metrics")
    from engagement_metrics import EngagementTracker

    tracker = EngagementTracker()

    # Track new session
    tracker.track_session("eng-test-1")
    test("Session tracked", "eng-test-1" in tracker.sessions)
    test("Turn count starts at 0", tracker.sessions["eng-test-1"]["turn_count"] == 0)

    # Update turns
    tracker.update("eng-test-1", "scammer", 0)
    test("Turn count incremented", tracker.sessions["eng-test-1"]["turn_count"] == 1)
    test("Scammer message counted", tracker.sessions["eng-test-1"]["scammer_message_count"] == 1)

    tracker.update("eng-test-1", "user", 3)
    test("Intel count updated", tracker.sessions["eng-test-1"]["intelligence_extracted_count"] == 3)

    # Calculate impact
    impact = tracker.calculate_impact("eng-test-1")
    test("Impact has duration_seconds", "duration_seconds" in impact)
    test("Impact has turns_completed", impact["turns_completed"] == 2)
    test("Impact has intelligence_density", impact["intelligence_density"] == "high")  # >2
    test("Impact has estimated_victims_protected", "estimated_victims_protected" in impact)
    test("Impact has time_wasted_for_scammer", "time_wasted_for_scammer" in impact)

    # Auto-tracks unknown session
    impact2 = tracker.calculate_impact("unknown-session")
    test("Auto-creates session on calculate_impact", "unknown-session" in tracker.sessions)

    # Low intel density
    tracker.track_session("eng-test-2")
    tracker.update("eng-test-2", "scammer", 1)
    impact3 = tracker.calculate_impact("eng-test-2")
    test("Low intel density classified as medium", impact3["intelligence_density"] == "medium")

    # Spec-required keys
    test("Impact has engagementDurationSeconds", "engagementDurationSeconds" in impact)
    test("Impact has totalMessagesExchanged", "totalMessagesExchanged" in impact)

# ─────────────────────────────────────────────
# MODULE 7: Models (Pydantic)
# ─────────────────────────────────────────────
def test_models():
    set_module("models (Pydantic)")
    from models import Message, AnalyzeRequest, AnalyzeResponse, ExtractedIntelligence, GuviCallbackPayload
    from pydantic import ValidationError

    # Valid Message
    msg = Message(sender="scammer", text="Hello", timestamp=1000)
    test("Valid Message created", msg.sender == "scammer" and msg.text == "Hello")

    # Invalid Message — missing required field
    try:
        bad_msg = Message(sender="scammer", text="Hello")  # missing timestamp
        test("Missing timestamp rejected", False, "Should have raised ValidationError")
    except ValidationError:
        test("Missing timestamp rejected", True)

    # Valid AnalyzeRequest
    req = AnalyzeRequest(
        sessionId="sess-1",
        message=Message(sender="scammer", text="Test", timestamp=1000),
        conversationHistory=[]
    )
    test("Valid AnalyzeRequest created", req.sessionId == "sess-1")

    # AnalyzeRequest missing message
    try:
        bad_req = AnalyzeRequest(sessionId="sess-1")
        test("Missing message rejected", False)
    except ValidationError:
        test("Missing message rejected", True)

    # ExtractedIntelligence defaults
    intel = ExtractedIntelligence()
    test("Intel defaults to empty lists", intel.bankAccounts == [] and intel.upiIds == [])
    test("Intel emailAddresses defaults to empty", intel.emailAddresses == [])

    # AnalyzeResponse
    resp = AnalyzeResponse(reply="Hello ji")
    test("AnalyzeResponse created", resp.status == "success" and resp.reply == "Hello ji")

    # GuviCallbackPayload
    payload = GuviCallbackPayload(
        sessionId="s1", scamDetected=True, totalMessagesExchanged=5,
        extractedIntelligence={"bankAccounts": [], "upiIds": []},
        agentNotes="Test notes"
    )
    test("GuviCallbackPayload created", payload.sessionId == "s1" and payload.scamDetected)

# ─────────────────────────────────────────────
# MODULE 8: Config
# ─────────────────────────────────────────────
def test_config():
    set_module("config")
    from config import MY_API_KEY, OPENROUTER_BASE_URL, FREE_MODELS, GUVI_CALLBACK_URL

    test("API key is set", isinstance(MY_API_KEY, str) and len(MY_API_KEY) > 0)
    test("OpenRouter base URL is valid", "openrouter.ai" in OPENROUTER_BASE_URL)
    test("Free models list has 4 models", len(FREE_MODELS) == 4)
    test("GUVI callback URL is HTTPS", GUVI_CALLBACK_URL.startswith("https://"))
    test("GUVI URL points to hackathon endpoint", "hackathon.guvi.in" in GUVI_CALLBACK_URL)

# ─────────────────────────────────────────────
# MODULE 9: Integration — FastAPI app (TestClient)
# ─────────────────────────────────────────────
def test_api_integration():
    set_module("API Integration (TestClient)")
    try:
        from fastapi.testclient import TestClient
        from main import app
    except ImportError:
        test("FastAPI TestClient available", False, "httpx not installed")
        return

    client = TestClient(app)
    API_KEY = "sentinal-hackathon-2026"
    headers = {"x-api-key": API_KEY, "Content-Type": "application/json"}

    # Health check
    r = client.get("/")
    test("GET / returns 200", r.status_code == 200)
    test("GET / returns ok status", r.json().get("status") == "ok")

    r2 = client.get("/health")
    test("GET /health returns healthy", r2.json().get("status") == "healthy")

    # Auth — bad key
    r3 = client.post("/analyze", headers={"x-api-key": "wrong-key", "Content-Type": "application/json"},
                     json={"sessionId":"s","message":{"sender":"s","text":"t","timestamp":1}})
    test("Bad API key returns 401", r3.status_code == 401)

    # Validation — missing message
    r4 = client.post("/analyze", headers=headers, json={"sessionId": "s"})
    test("Missing message returns 422", r4.status_code == 422)

    # Valid scam message
    payload = {
        "sessionId": "integration-test-1",
        "message": {
            "sender": "scammer",
            "text": "Your bank account is blocked. Call +919876543210 immediately to verify KYC. Send ₹500 to fraud@upi.",
            "timestamp": int(time.time() * 1000)
        },
        "conversationHistory": []
    }
    r5 = client.post("/analyze", headers=headers, json=payload)
    test("Scam message returns 200", r5.status_code == 200)
    data = r5.json()
    test("Response has status=success", data.get("status") == "success")
    test("Response has reply", isinstance(data.get("reply"), str) and len(data["reply"]) > 0)
    test("Scam detected", data.get("scamDetected") == True)
    test("extractedIntelligence present", "extractedIntelligence" in data)

    intel = data.get("extractedIntelligence", {})
    test("Phone number extracted", "+919876543210" in intel.get("phoneNumbers", []),
         f"phones={intel.get('phoneNumbers')}")
    test("UPI ID extracted", "fraud@upi" in intel.get("upiIds", []),
         f"upis={intel.get('upiIds')}")
    test("scamAnalysis present", "scamAnalysis" in data)
    test("scammerProfile present", "scammerProfile" in data)
    test("engagementMetrics present", "engagementMetrics" in data)

    # Multi-turn — second message adds bank account
    payload2 = {
        "sessionId": "integration-test-1",
        "message": {
            "sender": "scammer",
            "text": "Transfer to bank account 12345678901234 urgently",
            "timestamp": int(time.time() * 1000)
        },
        "conversationHistory": [
            payload["message"],
            {"sender": "user", "text": "Oh no what happened?", "timestamp": int(time.time() * 1000)}
        ]
    }
    r6 = client.post("/analyze", headers=headers, json=payload2)
    data2 = r6.json()
    intel2 = data2.get("extractedIntelligence", {})
    test("Multi-turn: bank account extracted", "12345678901234" in intel2.get("bankAccounts", []),
         f"banks={intel2.get('bankAccounts')}")
    test("Multi-turn: previous phone preserved", "+919876543210" in intel2.get("phoneNumbers", []),
         f"phones={intel2.get('phoneNumbers')}")
    test("Multi-turn: previous UPI preserved", "fraud@upi" in intel2.get("upiIds", []),
         f"upis={intel2.get('upiIds')}")

    # Benign message
    payload3 = {
        "sessionId": "integration-test-benign",
        "message": {
            "sender": "user",
            "text": "Hey, want to grab coffee tomorrow?",
            "timestamp": int(time.time() * 1000)
        },
        "conversationHistory": []
    }
    r7 = client.post("/analyze", headers=headers, json=payload3)
    data3 = r7.json()
    test("Benign message returns success", data3.get("status") == "success")
    test("Benign message: scam NOT detected", data3.get("scamDetected") == False)

    # Dual endpoint /api/analyze
    r8 = client.post("/api/analyze", headers=headers, json=payload3)
    test("/api/analyze endpoint works", r8.status_code == 200)

    # Debug endpoint
    r9 = client.post("/debug/session/integration-test-1", headers=headers)
    test("Debug endpoint returns session data", r9.status_code == 200)
    debug_data = r9.json()
    test("Debug shows scam_detected=True", debug_data.get("scam_detected") == True)
    test("Debug shows message_count >= 2", debug_data.get("message_count", 0) >= 2)

# ─────────────────────────────────────────────
# RUNNER & REPORT
# ─────────────────────────────────────────────
def run_all():
    print("\n" + "█"*60)
    print("  HONEYPOT AGENT — COMPREHENSIVE TEST SUITE")
    print("█"*60)

    modules = [
        ("Scam Detector", test_scam_detector),
        ("Intelligence Extractor", test_intelligence),
        ("Agent Persona", test_agent_persona),
        ("ScammerDNA", test_scammer_dna),
        ("Session Manager", test_session_manager),
        ("Engagement Metrics", test_engagement_metrics),
        ("Pydantic Models", test_models),
        ("Config", test_config),
        ("API Integration", test_api_integration),
    ]

    for name, fn in modules:
        try:
            fn()
        except Exception as e:
            set_module(name + " [CRASHED]")
            test(f"Module execution", False, f"Exception: {e}")
            traceback.print_exc()

    # ─── REPORT ───
    print("\n\n" + "█"*60)
    print("  FINAL TEST REPORT")
    print("█"*60)

    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")

    # Per-module summary
    modules_seen = []
    for r in results:
        if r["module"] not in modules_seen:
            modules_seen.append(r["module"])

    print(f"\n{'Module':<35} {'Pass':>6} {'Fail':>6} {'Total':>6}")
    print("-" * 60)
    for mod in modules_seen:
        mod_results = [r for r in results if r["module"] == mod]
        mp = sum(1 for r in mod_results if r["status"] == "PASS")
        mf = sum(1 for r in mod_results if r["status"] == "FAIL")
        status_icon = "✅" if mf == 0 else "❌"
        print(f"  {status_icon} {mod:<32} {mp:>6} {mf:>6} {len(mod_results):>6}")

    print("-" * 60)
    pct = (passed / total * 100) if total > 0 else 0
    overall_icon = "✅" if failed == 0 else "⚠️"
    print(f"  {overall_icon} {'TOTAL':<32} {passed:>6} {failed:>6} {total:>6}")
    print(f"\n  Pass Rate: {pct:.1f}%")

    if failed > 0:
        print(f"\n  ❌ FAILED TESTS:")
        for r in results:
            if r["status"] == "FAIL":
                print(f"     [{r['module']}] {r['test']}" + (f" — {r['detail']}" if r['detail'] else ""))

    print(f"\n{'█'*60}\n")

    # Write JSON report
    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_tests": total,
        "passed": passed,
        "failed": failed,
        "pass_rate": f"{pct:.1f}%",
        "modules": {}
    }
    for mod in modules_seen:
        mod_results = [r for r in results if r["module"] == mod]
        report["modules"][mod] = {
            "passed": sum(1 for r in mod_results if r["status"] == "PASS"),
            "failed": sum(1 for r in mod_results if r["status"] == "FAIL"),
            "tests": mod_results
        }

    with open("test_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("  📄 Report saved to test_report.json")

    return failed == 0

if __name__ == "__main__":
    success = run_all()
    sys.exit(0 if success else 1)
