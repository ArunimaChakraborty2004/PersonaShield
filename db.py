
import pymongo
from datetime import datetime
from pymongo import MongoClient

client = MongoClient("mongodb+srv://personashield:LB9TTahMGxKG8AEk@cluster0.bnksngc.mongodb.net/?appName=Cluster0")
db = client["persona_shield"]
messages = db["logs"]

try:
    client.admin.command('ping')
    print("✅ Connected to MongoDB Atlas")
except Exception as e:
    print("❌ Connection failed:", e)
def save_message(text, score, threat_type, matched_keywords=None,
                 matched_phrases=None, severity=None, explanation=None,
                 recommendation=None, ai_powered=False):
    messages.insert_one({
        "text": text,
        "score": score,
        "threat_type": threat_type,
        "matched_keywords": matched_keywords or [],
        "matched_phrases": matched_phrases or [],
        "severity": severity or "safe",
        "explanation": explanation or "",
        "recommendation": recommendation or "",
        "ai_powered": ai_powered,
        "timestamp": datetime.utcnow()
    })

def update_feedback(entry_id, feedback_value):
    messages.update_one({"_id": entry_id}, {"$set": {"feedback": feedback_value}})
