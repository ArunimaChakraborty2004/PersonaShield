
import os
import sys
import pymongo
from datetime import datetime
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv("En.env")

MONGO_URI = os.getenv("MONGO_URI")

if not MONGO_URI:
    print("❌ CRITICAL: MONGO_URI environment variable is missing. Please check your .env file.")
    sys.exit(1)

try:
    client = MongoClient(MONGO_URI)
    db = client["persona_shield"]
    messages = db["logs"]
    client.admin.command('ping')
    print("✅ Connected to MongoDB Atlas")
except Exception as e:
    print(f"❌ Database connection failed: {e}")
    sys.exit(1)
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
