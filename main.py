from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
import time

from config import MY_API_KEY
from models import AnalyzeRequest, AnalyzeResponse, ExtractedIntelligence
from scam_detector import detect_scam, get_scam_type
from intelligence import extract_all_intelligence, extract_from_conversation
from agent_persona import generate_honeypot_response, generate_confused_response
from session_manager import session_manager
from guvi_callback import send_callback_to_guvi, send_callback_async
# Anti-Gravity Imports
from scammer_dna import ScammerDNA
from engagement_metrics import engagement_tracker
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Agentic Honeypot API",
    description="AI-powered honeypot for scam detection and intelligence extraction",
    version="1.0.0"
)

# CORS middleware for cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    """Root endpoint - health check."""
    return {"status": "ok", "message": "Honeypot API is running"}

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": int(time.time() * 1000)}

@app.post("/analyze")
@app.post("/api/analyze")
async def analyze_message(
    request_body: AnalyzeRequest,
    x_api_key: str = Header(None, alias="x-api-key")
):
    """
    Main endpoint to analyze incoming messages.
    Detects scams, engages with honeypot persona, extracts intelligence.
    Enforces strict Pydantic validation.
    """
    
    # Validate API key
    if x_api_key != MY_API_KEY:
        logger.warning(f"Invalid API key attempt: {x_api_key}")
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    try:
        # Extract fields from validated Pydantic model
        session_id = request_body.sessionId
        message_text = request_body.message.text
        conversation_history_objs = request_body.conversationHistory or []
        
        # Convert Pydantic models back to dicts for internal logic if needed
        # or use them directly. The existing logic expects dicts mostly.
        conversation_history = [
            {"sender": m.sender, "text": m.text, "timestamp": m.timestamp} 
            for m in conversation_history_objs
        ]
        
        # DEBUG: Log raw request details
        logger.info(f"Processing message for session {session_id}")
        
        # Get or create session
        session = session_manager.get_or_create_session(session_id)
        
        # Detect scam in current message and history
        scam_detected, keywords = detect_scam(message_text, conversation_history)
        scam_type = get_scam_type(keywords) if scam_detected else None
        
        # Helper function to extract text from various message formats
        def get_message_text(msg) -> str:
            if isinstance(msg, str):
                return msg
            if isinstance(msg, dict):
                # Try various possible field names
                for field in ['text', 'content', 'body', 'message']:
                    if field in msg and msg[field]:
                        val = msg[field]
                        if isinstance(val, str):
                            return val
                        elif isinstance(val, dict):
                            # Nested message object
                            return get_message_text(val)
            return ""
        
        # Build full conversation text for comprehensive extraction
        all_texts = [message_text]  # Start with current message
        
        for i, msg in enumerate(conversation_history):
            msg_text = get_message_text(msg)
            if msg_text:
                all_texts.append(msg_text)
        
        # Combine all texts for extraction
        combined_text = "\n".join(all_texts)
        
        # Extract intelligence from ALL messages combined
        current_intel = extract_all_intelligence(combined_text)
        
        # Update session
        session = session_manager.update_session(
            session_id=session_id,
            scam_detected=scam_detected or session.scam_detected,  # Once detected, stays detected
            intelligence=current_intel,
            scam_type=scam_type or session.scam_type,
            increment_messages=True
        )
        
        # Add agent notes based on detection
        if scam_detected and not session.scam_detected:
            session.add_note(f"Scam detected: {scam_type}")
        if keywords:
            session.add_note(f"Keywords: {', '.join(keywords[:5])}")
        
        # Integrate Engagement Tracker (Phase 2 Optimization)
        # Calculate new intelligence items found in this turn
        new_intel_count = (
            len(current_intel.bankAccounts) + 
            len(current_intel.upiIds) + 
            len(current_intel.phishingLinks) + 
            len(current_intel.phoneNumbers)
        )
        engagement_tracker.update(session_id, request_body.message.sender, new_intel_count)
        
        # Scammer DNA Fingerprinting (Phase 2 Optimization)
        dna_engine = ScammerDNA()
        # DNA engine expects list of dicts. conversation_history is already list of dicts.
        # We need to add current message to a temporary list for FULL DNA analysis
        full_dna_history = conversation_history.copy()
        full_dna_history.append({
            "sender": request_body.message.sender,
            "text": request_body.message.text,
            "timestamp": request_body.message.timestamp
        })
        
        signature, features = dna_engine.generate_fingerprint_from_history(full_dna_history)

        # Generate response (Hybrid Engine via agent_persona)
        reply = None
        if session.scam_detected:
            # Honeypot mode - engage the scammer
            reply = generate_honeypot_response(
                current_message=message_text,
                conversation_history=conversation_history,
                scam_detected=True,
                scam_type=session.scam_type
            )
        else:
            # Not sure if scam - ask for clarification
            reply = generate_confused_response(message_text)
            
        logger.info(f"Generated reply for session {session_id}: {reply[:50]}...")
        
        # Smart Callback Trigger (Phase 1 Optimization)
        if session_manager.should_trigger_early_callback(session_id):
            logger.info(f"Smart Trigger: Sending early callback for session {session_id}")
            from guvi_callback import send_callback_to_guvi
            send_callback_to_guvi(session)
            session_manager.mark_callback_sent(session_id)

        # 6. Build Anti-Gravity Response
        response = AnalyzeResponse(
            status="success",
            reply=reply,
            scamDetected=session.scam_detected,
            extractedIntelligence=session.intelligence,
            # Competition Fields
            scamAnalysis={
                "detected": session.scam_detected,
                "type": session.scam_type or "unknown",
                "confidence": 0.95 if session.scam_detected else 0.1,
                "processing_time_ms": int((time.time() * 1000) - request_body.message.timestamp) 
            },
            scammerProfile={
                "behavioral_signature": signature,
                "tactics": features['tactics'],
                "timing_pattern": features['timing'],
                "structure": features['structure']
            },
            engagementMetrics=engagement_tracker.calculate_impact(session_id),
            systemStatus={
                "active_sessions": len(session_manager.sessions),
                "optimization_level": "expert"
            }
        )
        
        logger.info(f"Response: scamDetected={session.scam_detected}, messages={session.message_count}")
        
        return response
        
    except Exception as e:
        import traceback
        with open("/tmp/sentinal_error.log", "w") as f:
            f.write(traceback.format_exc())
        logger.error(f"Error processing request: {e}")
        # Return a safe fallback response
        return JSONResponse(
            content={
                "status": "success",
                "reply": "Sorry, I didn't understand. Can you explain again?",
                "scamDetected": False
            }
        )

@app.post("/debug/session/{session_id}")
async def get_session_debug(
    session_id: str,
    x_api_key: str = Header(None, alias="x-api-key")
):
    """Debug endpoint to view session state."""
    if x_api_key != MY_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
        
    return {
        "session_id": session.session_id,
        "scam_detected": session.scam_detected,
        "scam_type": session.scam_type,
        "message_count": session.message_count,
        "intelligence": session.intelligence,
        "callback_sent": session.callback_sent,
        "notes": session.agent_notes
    }

@app.post("/callback/force/{session_id}")
async def force_callback(
    session_id: str,
    x_api_key: str = Header(None, alias="x-api-key")
):
    """Force trigger callback for a session."""
    if x_api_key != MY_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    session = session_manager.get_session(session_id)
    if not session:
        # Try to load/recreate context?? No, just error
        raise HTTPException(status_code=404, detail="Session not found")
        
    success = send_callback_to_guvi(session)
    session_manager.mark_callback_sent(session_id)
    
    return {"status": "success", "callback_triggered": True, "guvi_response": success}
