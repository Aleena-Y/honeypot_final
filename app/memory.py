
SESSION_STORE = {}

def get_session(session_id):
    if session_id not in SESSION_STORE:
        SESSION_STORE[session_id] = {
            "messages": [],
            "intelligence": {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "emailAddresses": [],
                "suspiciousKeywords": [],
                "scamScenarios": {}
            },
            "scamDetected": False
        }
    return SESSION_STORE[session_id]
