import requests
import logging
from config import GUVI_CALLBACK_URL
from session_manager import SessionData

logger = logging.getLogger(__name__)

def send_callback_to_guvi(session: SessionData) -> bool:
    """
    Send final intelligence to GUVI evaluation endpoint.
    Returns True if successful, False otherwise.
    """
    # Calculate engagement duration
    from datetime import datetime
    duration_seconds = int((datetime.now() - session.created_at).total_seconds())
    
    payload = {
        "sessionId": session.session_id,
        "scamDetected": session.scam_detected,
        "totalMessagesExchanged": session.message_count,
        "extractedIntelligence": {
            "bankAccounts": session.intelligence.bankAccounts,
            "upiIds": session.intelligence.upiIds,
            "phishingLinks": session.intelligence.phishingLinks,
            "phoneNumbers": session.intelligence.phoneNumbers,
            "emailAddresses": session.intelligence.emailAddresses,
            "suspiciousKeywords": session.intelligence.suspiciousKeywords
        },
        "engagementMetrics": {
            "totalMessagesExchanged": session.message_count,
            "engagementDurationSeconds": duration_seconds
        },
        "agentNotes": session.get_notes_string()
    }
    
    try:
        logger.info(f"Sending callback to GUVI for session {session.session_id}")
        logger.info(f"Payload: {payload}")
        
        response = requests.post(
            GUVI_CALLBACK_URL,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            logger.info(f"GUVI callback successful for session {session.session_id}")
            return True
        else:
            logger.warning(f"GUVI callback returned status {response.status_code}: {response.text}")
            return False
            
    except requests.exceptions.Timeout:
        logger.error(f"GUVI callback timeout for session {session.session_id}")
        return False
    except requests.exceptions.RequestException as e:
        logger.error(f"GUVI callback error for session {session.session_id}: {e}")
        return False

def send_callback_async(session: SessionData):
    """
    Send callback in background (non-blocking).
    Used when we don't want to delay the API response.
    """
    import threading
    
    def _send():
        send_callback_to_guvi(session)
    
    thread = threading.Thread(target=_send)
    thread.daemon = True
    thread.start()
