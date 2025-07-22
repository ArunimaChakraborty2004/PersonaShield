
import pymongo
from datetime import datetime
from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/")
db = client["persona_shield"]
messages = db["logs"]

def save_message(text, score, threat_type, matched_keywords=None, matched_phrases=None):
    messages.insert_one({
        "text": text,
        "score": score,
        "threat_type": threat_type,
        "matched_keywords": matched_keywords or [],
        "matched_phrases": matched_phrases or [],
        "timestamp": datetime.utcnow()
    })

def update_feedback(entry_id, feedback_value):
    messages.update_one({ "_id": entry_id }, { "$set": { "feedback": feedback_value } })


