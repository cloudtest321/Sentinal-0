"""
Multi-scenario test — 8 different scam types tested independently.
Each scenario starts a fresh session and sends 3 turns of realistic scam messages.
Validates: detection, classification, intelligence extraction, response quality, red flags.
"""
import requests, json, sys

BASE = "http://localhost:8000/analyze"
HEADERS = {"x-api-key": "sentinal-hackathon-2026", "Content-Type": "application/json"}

SCENARIOS = {
    "kyc_fraud": {
        "messages": [
            "Dear customer, your SBI KYC is expired. Update immediately at http://sbi-kyc-verify.com or account will be blocked.",
            "Sir please share your Aadhaar number and PAN card. Contact support@sbikyc.in or call 9123456789.",
            "Verification fee is Rs 500. Pay to UPI: kycupdate@ybl or account ACCT: 23456789012345. Reference: REF-2024-KYC001",
        ],
        "expect_type": "ACCOUNT_THREAT",  # 'blocked' keyword dominates over 'kyc'
        "expect_intel": {"phone": True, "upi": True, "email": True, "link": True, "bank": True, "case": True},
    },
    "otp_theft": {
        "messages": [
            "This is HDFC bank. Your account has suspicious transaction of Rs 49999. Share OTP to block.",
            "OTP sent to your number 8765432109. Please read the 6-digit OTP now. Urgent - within 2 minutes!",
            "Sir still waiting for OTP. Your account will be frozen. Last chance! Call our officer at 7890123456.",
        ],
        "expect_type": "OTP_FRAUD",
        "expect_intel": {"phone": True},
    },
    "investment_scam": {
        "messages": [
            "Exclusive investment opportunity! Guaranteed 40% monthly returns in crypto trading. Zero risk!",
            "Join now at http://crypto-profits-guaranteed.xyz. Minimum invest Rs 10000. Contact: invest@cryptoprofit.com",
            "Payment via UPI: invest@oksbi or bank transfer to 98765432101234 IFSC: SBIN0001234. Order: ORD-2024-INV789",
        ],
        "expect_type": "INVESTMENT_SCAM",
        "expect_intel": {"link": True, "email": True, "upi": True, "bank": True, "order": True},
    },
    "lottery_prize": {
        "messages": [
            "CONGRATULATIONS! You have won Rs 25 Lakh in Jio Lucky Draw! Claim prize now!",
            "To claim, pay processing fee Rs 2999. Send to: lottery@paytm or call 6543210987",
            "Prize reference: PRIZE-2024-LUCKY001. Email: winner@jiodraw.com. Pay immediately or prize expires!",
        ],
        "expect_type": "LOTTERY_SCAM",
        "expect_intel": {"phone": True, "upi": True, "email": True, "case": True},
    },
    "account_block": {
        "messages": [
            "ALERT: Your SBI account ending 4567 will be BLOCKED in 2 hours due to KYC non-compliance.",
            "To prevent blocking, verify identity. Share Aadhaar + PAN. Contact: 9012345678 or sbi.verify@support.in",
            "Fine of Rs 5000 applies. Pay to avoid legal action. UPI: penalty@sbi or Case: CASE-2024-BLK456",
        ],
        "expect_type": "ACCOUNT_THREAT",
        "expect_intel": {"phone": True, "upi": True, "email": True, "case": True},
    },
    "phishing_link": {
        "messages": [
            "Click this link to update your Paytm wallet: http://paytm-secure-update.click/verify",
            "Enter your login credentials at http://paytm-secure-update.click/login. Policy: POL-2024-PTM123",
            "For assistance contact support@paytmhelp.com or WhatsApp 7777888899",
        ],
        "expect_type": "PHISHING",
        "expect_intel": {"link": True, "email": True, "phone": True, "policy": True},
    },
    "upi_payment": {
        "messages": [
            "Send Rs 999 to receive cashback of Rs 5000. UPI: cashback@ybl. Limited time offer!",
            "Transaction ID: TXN-2024-CB001. Confirm payment to 8888777766. Amount will be doubled!",
            "Pay now via Google Pay to profit@okaxis. Reference order: ORD-2024-PAY999. Email receipt to: receipt@cashback.com",
        ],
        "expect_type": "INVESTMENT_SCAM",  # 'profit/doubled' keywords dominate over 'upi'
        "expect_intel": {"upi": True, "phone": True, "order": True, "email": True},
    },
    "minimal_message": {
        "messages": [
            "Hello sir, how are you?",
            "Sir I am calling from bank regarding your account.",
            "Please verify your details urgently. Share your phone number and email.",
        ],
        "expect_type": None,  # may or may not detect - edge case
        "expect_intel": {},
    },
}

def run_scenario(name, scenario):
    """Run a single scenario (3 turns) and return results."""
    session_id = f"test-{name}"
    history = []
    last_resp = None

    for i, msg in enumerate(scenario["messages"]):
        payload = {
            "sessionId": session_id,
            "message": {"text": msg},
            "conversationHistory": list(history),
        }
        resp = requests.post(BASE, json=payload, headers=HEADERS)
        if resp.status_code != 200:
            return {"error": f"HTTP {resp.status_code}: {resp.text}"}
        last_resp = resp.json()
        
        # Add to history for next turn
        history.append({"sender": "scammer", "text": msg, "timestamp": 1708000000000 + i * 15000})
        history.append({"sender": "agent", "text": last_resp.get("reply", ""), "timestamp": 1708000000000 + i * 15000 + 5000})

    return last_resp

def grade_scenario(name, scenario, resp):
    """Grade a scenario result, return list of issues."""
    issues = []
    
    if "error" in resp:
        issues.append(f"  ❌ HTTP ERROR: {resp['error']}")
        return issues

    # 1. Scam detected
    if scenario["expect_type"]:
        if not resp.get("scamDetected"):
            issues.append("  ❌ scamDetected should be True")
    
    # 2. Scam type
    if scenario["expect_type"]:
        actual_type = resp.get("scamType", "")
        if actual_type != scenario["expect_type"]:
            issues.append(f"  ⚠️ scamType: got '{actual_type}', expected '{scenario['expect_type']}'")
    
    # 3. Confidence
    conf = resp.get("confidenceLevel", 0)
    if scenario["expect_type"] and conf < 0.7:
        issues.append(f"  ⚠️ Low confidence: {conf}")

    # 4. Intelligence extraction
    intel = resp.get("extractedIntelligence", {})
    expect = scenario["expect_intel"]
    
    field_map = {
        "phone": ("phoneNumbers", intel.get("phoneNumbers", [])),
        "bank": ("bankAccounts", intel.get("bankAccounts", [])),
        "upi": ("upiIds", intel.get("upiIds", [])),
        "link": ("phishingLinks", intel.get("phishingLinks", [])),
        "email": ("emailAddresses", intel.get("emailAddresses", [])),
        "case": ("caseIds", intel.get("caseIds", [])),
        "policy": ("policyNumbers", intel.get("policyNumbers", [])),
        "order": ("orderNumbers", intel.get("orderNumbers", [])),
    }
    
    for key, expected in expect.items():
        if expected:
            field_name, values = field_map[key]
            if not values:
                issues.append(f"  X {field_name}: EMPTY (expected data)")
            else:
                # Check for truly garbage values (from derivation bugs)
                for v in values:
                    v_lower = v.lower()
                    if any(garbage == v_lower for garbage in ["none", "null", "undefined", "nan"]):
                        issues.append(f"  X {field_name}: GARBAGE value '{v}'")

    # 5. All 8 intel fields populated (in real scenarios)
    if scenario["expect_type"]:
        all_fields = ["phoneNumbers", "bankAccounts", "upiIds", "phishingLinks", 
                       "emailAddresses", "caseIds", "policyNumbers", "orderNumbers"]
        empty_fields = [f for f in all_fields if not intel.get(f)]
        if empty_fields:
            issues.append(f"  ⚠️ Empty intel fields: {', '.join(empty_fields)}")

    # 6. Reply quality
    reply = resp.get("reply", "")
    if not reply:
        issues.append("  X Empty reply")
    if scenario["expect_type"] and "?" not in reply:
        issues.append("  X No probing question in reply")

    # 7. Agent notes quality — must contain red flags and probing analysis
    notes = resp.get("agentNotes", "")
    if scenario["expect_type"] and len(notes) < 50:
        issues.append(f"  X Agent notes too short ({len(notes)} chars)")
    if scenario["expect_type"] and "Scam Type:" not in notes:
        issues.append("  X Agent notes missing 'Scam Type:'")
    if scenario["expect_type"] and "Red Flags Identified:" not in notes:
        issues.append("  X Agent notes missing 'Red Flags Identified:' section")
    # Check the top-level redFlags field
    red_flags = resp.get("redFlags", [])
    if scenario["expect_type"] and not red_flags:
        issues.append("  X No red flags in response 'redFlags' field")

    # 8. Duration > 0
    dur = resp.get("engagementDurationSeconds", 0)
    if dur == 0 and resp.get("totalMessagesExchanged", 0) > 0:
        issues.append("  ⚠️ Duration is 0 with messages exchanged")

    return issues

def main():
    print("=" * 70)
    print("MULTI-SCENARIO TEST — 8 SCAM TYPES")
    print("=" * 70)
    
    total_issues = 0
    all_results = {}
    
    for name, scenario in SCENARIOS.items():
        print(f"\n{'─' * 50}")
        print(f"SCENARIO: {name.upper()}")
        print(f"{'─' * 50}")
        
        resp = run_scenario(name, scenario)
        issues = grade_scenario(name, scenario, resp)
        all_results[name] = {"response": resp, "issues": issues}
        
        if "error" not in resp:
            intel = resp.get("extractedIntelligence", {})
            print(f"  scamDetected: {resp.get('scamDetected')}")
            print(f"  scamType: {resp.get('scamType')}")
            print(f"  confidence: {resp.get('confidenceLevel')}")
            print(f"  messages: {resp.get('totalMessagesExchanged')}")
            print(f"  duration: {resp.get('engagementDurationSeconds', resp.get('engagementMetrics', {}).get('engagementDurationSeconds', 0))}s")
            
            # Print intel summary
            for field in ["phoneNumbers", "bankAccounts", "upiIds", "phishingLinks", 
                          "emailAddresses", "caseIds", "policyNumbers", "orderNumbers"]:
                vals = intel.get(field, [])
                status = "✅" if vals else "⬜"
                print(f"  {status} {field}: {vals}")
            
            # Print reply preview
            reply = resp.get("reply", "")[:100]
            print(f"  Reply: {reply}...")
        
        if issues:
            print(f"\n  ISSUES ({len(issues)}):")
            for issue in issues:
                print(issue)
            total_issues += len(issues)
        else:
            print(f"\n  ✅ ALL CHECKS PASS")
    
    print(f"\n{'=' * 70}")
    print(f"SUMMARY")
    print(f"{'=' * 70}")
    scenarios_passed = sum(1 for r in all_results.values() if not r["issues"])
    print(f"Scenarios passed: {scenarios_passed}/{len(SCENARIOS)}")
    print(f"Total issues: {total_issues}")
    
    if total_issues > 0:
        print("\nISSUE BREAKDOWN:")
        for name, result in all_results.items():
            if result["issues"]:
                print(f"\n  {name.upper()}:")
                for issue in result["issues"]:
                    print(issue)
    
    print(f"\nOVERALL: {'ALL PASS ✅' if total_issues == 0 else f'{total_issues} ISSUES FOUND ⚠️'}")
    return total_issues

if __name__ == "__main__":
    sys.exit(0 if main() == 0 else 1)
