
import os
import sys
import pymongo
from datetime import datetime
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv("En.env")

MONGO_URI = os.getenv("MONGO_URI")

if not MONGO_URI:
    print("CRITICAL: MONGO_URI environment variable is missing. Please check your En.env file.")
    sys.exit(1)

try:
    client = MongoClient(MONGO_URI)
    db = client["persona_shield"]
    messages = db["logs"]
    url_logs = db["url_logs"]
    url_intelligence = db["url_intelligence"]
    client.admin.command('ping')
    print("Connected to MongoDB Atlas successfully.")
except Exception as e:
    print(f"Database connection failed: {e}")
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

def get_url_intelligence(domain):
    return url_intelligence.find_one({"domain": domain})

def update_url_intelligence(domain, risk_score, confidence):
    now = datetime.utcnow()
    url_intelligence.update_one(
        {"domain": domain},
        {
            "$inc": {"times_seen": 1},
            "$set": {"last_seen": now, "risk_score": risk_score, "confidence": confidence},
            "$setOnInsert": {"first_seen": now, "domain": domain}
        },
        upsert=True
    )

def save_url_scan(url, risk_score, status, explanation, recommendation, sources=None, confidence=0, threat_type="Unknown", domain_age=None, ai_powered=False):
    url_logs.insert_one({
        "url": url,
        "risk_score": risk_score,
        "status": status,
        "explanation": explanation,
        "recommendation": recommendation,
        "sources": sources or [],
        "confidence": confidence,
        "threat_type": threat_type,
        "domain_age": domain_age,
        "ai_powered": ai_powered,
        "timestamp": datetime.utcnow()
    })
