"""
PersonaShield AI Analyzer — Cohere Integration
Falls back to keyword detection if no API key is set.
Automatically loads API key from En.env file.
"""

import os
import json
import re
from pathlib import Path
from threat_detector import detect_threat_json

def _load_env_file():
    """Load key=value pairs from En.env file in the same directory."""
    env_path = Path(__file__).parent / "En.env"
    if env_path.exists():
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    key, _, value = line.partition("=")
                    os.environ.setdefault(key.strip(), value.strip())

_load_env_file()

COHERE_API_KEY = os.environ.get("COHERE_API_KEY", "")
_cohere_client = None

def _get_client():
    global _cohere_client
    if _cohere_client is not None:
        return _cohere_client
    if not COHERE_API_KEY:
        return None
    try:
        import cohere
        import httpx
        _cohere_client = cohere.Client(COHERE_API_KEY, httpx_client=httpx.Client(verify=False))
        print("[AI] Cohere client loaded successfully.")
    except Exception as e:
        print(f"[AI] Failed to load Cohere: {e}")
        _cohere_client = None
    return _cohere_client


SECURITY_PROMPT = """You are PersonaShield, an expert cybersecurity AI that detects social engineering, phishing, manipulation, and digital threats in messages.

Analyze the following message for threats:

MESSAGE: "{message}"

Respond ONLY with valid JSON (no markdown, no extra text) in this exact format:
{{
  "score": <integer 0-10>,
  "type": "<one of: Safe, Urgency, Phishing, Impersonation, Info Theft, Redirect Scam, Secrecy, Manipulation, Multiple Threats>",
  "severity": "<one of: safe, low, medium, high, critical>",
  "explanation": "<2-3 sentence human-readable explanation of what threat tactics were found and why>",
  "recommendation": "<1 concise sentence on what the user should do>",
  "matched_keywords": [<list of suspicious words/phrases found>],
  "matched_phrases": [<list of full suspicious phrases found>]
}}

Scoring guide:
- 0-2: No threat / safe message
- 3-4: Mild concern (slightly suspicious tone)
- 5-6: Medium threat (clear manipulation or phishing signals)
- 7-8: High threat (multiple tactics, urgency + credentials)
- 9-10: Critical (clear attack, all major indicators present)
"""


def analyze_with_cohere(message: str) -> dict:
    """Run AI analysis using Cohere. Returns structured threat result."""
    client = _get_client()
    if client is None:
        return None  # Signal fallback

    try:
        prompt = SECURITY_PROMPT.format(message=message.replace('"', '\\"'))
        response = client.chat(
            message=prompt,
            model="command-r-08-2024"
        )
        raw = response.text.strip()

        # Strip markdown code fences if present
        raw = re.sub(r'^```(?:json)?\s*', '', raw, flags=re.MULTILINE)
        raw = re.sub(r'\s*```$', '', raw, flags=re.MULTILINE)

        result = json.loads(raw)

        # Ensure required fields
        result.setdefault("score", 0)
        result.setdefault("type", "Safe")
        result.setdefault("severity", "safe")
        result.setdefault("explanation", "")
        result.setdefault("recommendation", "")
        result.setdefault("matched_keywords", [])
        result.setdefault("matched_phrases", [])
        result["threat_type"] = result.get("type", "Safe")
        result["ai_powered"] = True

        return result

    except Exception as e:
        print(f"[AI] Cohere analysis error: {e}")
        return None


def analyze_message(message: str) -> dict:
    """
    Main entry point. Tries Cohere first, falls back to keyword detector.
    Always returns a fully-formed threat result dict.
    """
    # Try Cohere
    result = analyze_with_cohere(message)
    if result is not None:
        return result

    # Fallback: keyword detector
    base = detect_threat_json(message)
    score = base["score"]

    # Derive severity from score
    if score == 0:
        severity = "safe"
    elif score <= 3:
        severity = "low"
    elif score <= 5:
        severity = "medium"
    elif score <= 7:
        severity = "high"
    else:
        severity = "critical"

    # Build a decent explanation from keywords
    triggers = base.get("matched_keywords", []) + base.get("matched_phrases", [])
    if triggers:
        explanation = (
            f"This message contains suspicious indicators: {', '.join(triggers[:5])}. "
            f"These terms are commonly associated with {base.get('type', 'threat')} attacks. "
            "Review carefully before taking any action."
        )
        recommendation = "Do not click links or share personal information. Verify the sender through official channels."
    else:
        explanation = "No significant threat indicators were found in this message."
        recommendation = "This message appears safe, but always stay vigilant online."

    return {
        "score": score,
        "type": base.get("type", "Safe"),
        "threat_type": base.get("type", "Safe"),
        "severity": severity,
        "explanation": explanation,
        "recommendation": recommendation,
        "matched_keywords": base.get("matched_keywords", []),
        "matched_phrases": base.get("matched_phrases", []),
        "ai_powered": False
    }
