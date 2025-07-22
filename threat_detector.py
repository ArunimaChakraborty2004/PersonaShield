def detect_threat_with_triggers(message):
    message_lower = message.lower()
    score = 0
    matched_types = set()
    matched_keywords = []
    matched_phrases = []

    keywords = {
        "urgent": ("Urgency", 2),
        "immediately": ("Urgency", 2),
        "rush": ("Urgency", 2),
        "asap": ("Urgency", 2),
        "final notice": ("Urgency", 3),
        "deadline": ("Urgency", 2),
        "last warning": ("Urgency", 2),
        "hurry": ("Urgency", 2),
        "urgent action required": ("Urgency", 4),
        "immediate response needed": ("Urgency", 4),

        "verify": ("Impersonation", 3),
        "update credentials": ("Impersonation", 3),
        "official notice": ("Impersonation", 2),
        "security team": ("Impersonation", 2),
        "account": ("Impersonation", 2),
        "admin panel": ("Impersonation", 2),

        "password": ("Info Theft", 3),
        "otp": ("Info Theft", 2),
        "pin": ("Info Theft", 2),
        "ssn": ("Info Theft", 3),
        "secret key": ("Info Theft", 2),
        "login info": ("Info Theft", 2),
        "confirm details": ("Info Theft", 2),
        "upload": ("Info Theft", 2),
        "credentials": ("Info Theft", 2),

        "click here": ("Redirect Scam", 3),
        "tap to proceed": ("Redirect Scam", 2),
        "download now": ("Redirect Scam", 2),
        "attached document": ("Redirect Scam", 2),
        "reset link": ("Redirect Scam", 2),

        "don’t tell": ("Secrecy", 2),
        "private": ("Secrecy", 2),
        "hidden file": ("Secrecy", 2),
        "restricted": ("Secrecy", 2),
        "keep confidential": ("Secrecy", 3)
    }

    phrases = {
        "click below": ("Redirect Scam", 4),
        "final warning": ("Urgency", 4),
        "verify your identity": ("Impersonation", 4),
        "update your password": ("Info Theft", 4),
        "keep this confidential": ("Secrecy", 4),
        "reset via this link": ("Redirect Scam", 4),
        "download the attachment": ("Redirect Scam", 4),
        "confirm your password": ("Info Theft", 4),
        "only for you": ("Secrecy", 3),
        "restricted access": ("Secrecy", 3),
        "upload the credentials": ("Info Theft", 4),
        "update your account": ("Impersonation", 4),
        "final call": ("Urgency", 3),
        "click here immediately": ("Urgency", 3),
        "don't tell anyone": ("Secrecy", 4),
        "urgent call needed": ("Urgency", 4),
    "please call urgently": ("Urgency", 4),
    "call us immediately": ("Urgency", 4),
    }

    for phrase, (label, weight) in phrases.items():
        if phrase in message_lower:
            score += weight
            matched_phrases.append(phrase)
            matched_types.add(label)

    for word, (label, weight) in keywords.items():
        if word in message_lower:
            score += weight
            matched_keywords.append(word)
            matched_types.add(label)

    final_score = min(score, 10)

    if not matched_types:
        threat_type = "Safe"
    elif len(matched_types) == 1:
        threat_type = list(matched_types)[0]
    else:
        threat_type = "Multiple Threats"

    return final_score, threat_type, matched_keywords, matched_phrases


def detect_threat_json(message):
    score, threat_type, matched_keywords, matched_phrases = detect_threat_with_triggers(message)
    return {
        "score": score,
        "type": threat_type,
        "matched_keywords": matched_keywords,
        "matched_phrases": matched_phrases
    }

