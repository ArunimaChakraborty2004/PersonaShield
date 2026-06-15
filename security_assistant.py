import json
from bson import ObjectId
from ai_analyzer import _get_client
from db import messages, url_logs

ASSISTANT_PROMPT = """You are PersonaShield AI, a professional cybersecurity assistant and copilot. 

Your sole purpose is to help users understand cybersecurity threats, such as phishing, social engineering, malicious URLs, password security, scam detection, and safe browsing practices.

Guidelines:
1. Explain WHY something is dangerous clearly and concisely.
2. Explain HOW attacks work and HOW to stay safe.
3. Be educational and beginner-friendly, avoiding overly dense jargon where possible.
4. Focus ONLY on cybersecurity. If a user asks about anything unrelated (e.g., cooking recipes, general programming, sports), politely refuse and guide them back to cybersecurity.
5. NEVER provide offensive, illegal, or hacking instructions.
6. Provide your response in Markdown format.

If the user asks you to explain a recent scan, you will be provided with the scan context below. Use that context to explain why it was flagged, breaking down the specific indicators, risk score, and confidence.
"""

class MongoEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        return super().default(obj)

def ask_security_assistant(question, explicit_scan_id=None):
    client = _get_client()
    if not client:
        return {"answer": "Error: Cohere AI client is not available. Please check API keys.", "sources": []}

    context_data = None
    
    # Priority 1: Explicit context
    if explicit_scan_id:
        try:
            context_data = url_logs.find_one({"_id": ObjectId(explicit_scan_id)})
            if not context_data:
                context_data = messages.find_one({"_id": ObjectId(explicit_scan_id)})
        except:
            pass

    # Priority 2: Automatic latest scan detection fallback
    elif any(keyword in question.lower() for keyword in ["scan", "flagged", "result"]):
        latest_url = url_logs.find_one(sort=[("timestamp", -1)])
        latest_msg = messages.find_one(sort=[("timestamp", -1)])
        
        if latest_url and latest_msg:
            url_ts = latest_url.get("timestamp")
            msg_ts = latest_msg.get("timestamp")
            if url_ts and msg_ts:
                context_data = latest_url if url_ts > msg_ts else latest_msg
            elif url_ts:
                context_data = latest_url
            else:
                context_data = latest_msg
        elif latest_url:
            context_data = latest_url
        elif latest_msg:
            context_data = latest_msg

    prompt = ASSISTANT_PROMPT
    if context_data:
        try:
            prompt += f"\n\n--- RECENT SCAN CONTEXT ---\n{json.dumps(context_data, indent=2, cls=MongoEncoder)}\n"
        except Exception as json_e:
            with open("assistant_error.log", "a") as f:
                f.write(f"JSON Error: {json_e}\n")

    try:
        response = client.chat(
            message=question,
            preamble=prompt,
            model="command-r-08-2024"
        )
        return {
            "answer": response.text.strip(),
            "sources": [],
            "used_context": bool(context_data)
        }
    except Exception as e:
        print(f"[Assistant] Error: {e}")
        with open("assistant_error.log", "w") as f:
            import traceback
            f.write(f"Error: {str(e)}\n{traceback.format_exc()}\n")
        return {"answer": f"Sorry, I encountered an error while processing your request. Please check assistant_error.log.", "sources": [], "used_context": False}
