import time
from typing import Dict, List, Any

class EngagementTracker:
    def __init__(self):
        self.sessions = {}
    
    def track_session(self, session_id: str):
        """Initialize tracking for session"""
        if session_id not in self.sessions:
            self.sessions[session_id] = {
                'start_time': time.time(),
                'turn_count': 0,
                'scammer_message_count': 0,
                'intelligence_extracted_count': 0
            }
    
    def update(self, session_id: str, sender: str, intel_count: int = 0):
        """Update metrics per turn"""
        if session_id not in self.sessions:
            self.track_session(session_id)
        
        session = self.sessions[session_id]
        session['turn_count'] += 1
        
        if sender == 'scammer':
            session['scammer_message_count'] += 1
            
        # Update connection count if provided (cumulative is tricky, we'll just store max or update)
        # Assuming main.py passes the count of NEW intel or TOTAL intel. 
        # Let's assume TOTAL for simplicity or updated count.
        session['intelligence_extracted_count'] = max(session['intelligence_extracted_count'], intel_count)
    
    def calculate_impact(self, session_id: str) -> Dict[str, Any]:
        """Calculate time-waste impact"""
        if session_id not in self.sessions:
            self.track_session(session_id)
            
        session = self.sessions[session_id]
        elapsed_time = time.time() - session['start_time']
        
        # Estimate victims protected
        # Assumption: scammer can target 1 victim per 3 minutes (180s)
        potential_victims_protected = int(elapsed_time / 180)
        
        # Wasted time string
        minutes = int(elapsed_time // 60)
        seconds = int(elapsed_time % 60)
        time_str = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"
        
        return {
            "duration_seconds": int(elapsed_time),
            "engagementDurationSeconds": int(elapsed_time),
            "turns_completed": session['turn_count'],
            "totalMessagesExchanged": session['turn_count'],
            "intelligence_density": "high" if (session['intelligence_extracted_count'] > 2) else "medium",
            "estimated_victims_protected": max(0, potential_victims_protected),
            "time_wasted_for_scammer": time_str
        }

# Global instance
engagement_tracker = EngagementTracker()
