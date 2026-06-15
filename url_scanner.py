import re
from urllib.parse import urlparse
import json
import whois
from datetime import datetime
from ai_analyzer import _get_client
from openphish_checker import is_openphish_url
from db import get_url_intelligence, update_url_intelligence

# --- Threat Intelligence Lists ---

# Well-known URL shortener domains
URL_SHORTENERS = {
    'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'is.gd', 'ow.ly',
    'buff.ly', 'qr.ae', 'adf.ly', 'bl.ink', 'snip.ly', 'rb.gy',
    'short.io', 'tiny.cc', 'cutt.ly', 'v.gd', 'shrtco.de', 'clck.ru'
}

# TLDs commonly abused in phishing/spam campaigns
SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.club', '.online', '.site', '.cc', '.tk',
    '.ml', '.ga', '.cf', '.gq', '.pw', '.ws', '.biz', '.info',
    '.mobi', '.work', '.click', '.link', '.live', '.uno', '.icu',
    '.cyou', '.rest', '.surf', '.monster'
}

# Well-known legitimate brands - used to detect typosquatting
TRUSTED_BRANDS = [
    'paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook',
    'netflix', 'instagram', 'twitter', 'linkedin', 'dropbox', 'adobe',
    'bank', 'wellsfargo', 'chase', 'citibank', 'hsbc', 'barclays',
    'github', 'openai'
]

TRUSTED_DOMAINS = [
    'google.com', 'github.com', 'openai.com', 'amazon.com', 'microsoft.com', 
    'apple.com', 'paypal.com', 'linkedin.com', 'facebook.com', 'instagram.com',
    'twitter.com', 'netflix.com', 'dropbox.com', 'adobe.com'
]

# Keywords in path/query that indicate phishing attempts
PHISHING_PATH_KEYWORDS = [
    'verify', 'login', 'signin', 'account', 'password', 'passwd',
    'credential', 'recover', 'unlock', 'secure', 'update', 'validate',
    'confirm', 'billing', 'wallet', 'auth', 'authenticate', 'reset'
]

# Keywords in the domain itself that raise flags (brand impersonation)
PHISHING_DOMAIN_KEYWORDS = [
    'verify', 'secure', 'login', 'account', 'update', 'billing',
    'support', 'helpdesk', 'service', 'signin'
]

def is_trusted_domain(domain: str) -> bool:
    if domain in TRUSTED_DOMAINS:
        return True
    return any(domain.endswith('.' + td) for td in TRUSTED_DOMAINS)


def _extract_base_domain(netloc: str) -> str:
    """Strip port and return only the hostname."""
    return netloc.split(':')[0]

URL_SECURITY_PROMPT = """You are PersonaShield, an expert cybersecurity AI. Analyze this URL for threats:

URL: "{url}"

Respond ONLY with valid JSON (no markdown, no extra text) in this exact format:
{{
"risk_score": <integer 0-10>,
"status": "<Safe, Suspicious, or Malicious>",
"confidence": <integer 0-100>,
"explanation": "<2-3 sentence explanation of threats found (phishing, brand impersonation, etc)>",
"recommendation": "<1 concise sentence recommendation>",
"threat_type": "<e.g., Phishing, Malware, Brand Impersonation, Credential Harvesting, Safe>"
}}
"""

def analyze_url_with_cohere(url):
    client = _get_client()
    if not client:
        return None
    try:
        prompt = URL_SECURITY_PROMPT.format(url=url.replace('"', '\\"'))
        response = client.chat(message=prompt, model="command-r-08-2024")
        raw = response.text.strip()
        json_start = raw.find('{')
        json_end = raw.rfind('}')
        if json_start != -1 and json_end != -1:
            raw = raw[json_start:json_end+1]
        return json.loads(raw)
    except Exception as e:
        print(f"[AI URL] Cohere analysis error: {e}")
        return None

def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if type(creation_date) is list:
            for cd in creation_date:
                if isinstance(cd, datetime):
                    creation_date = cd
                    break
            if type(creation_date) is list:
                creation_date = creation_date[0]

        if not creation_date or not isinstance(creation_date, datetime):
            return None
            
        now_naive = datetime.now().replace(tzinfo=None)
        creation_naive = creation_date.replace(tzinfo=None)
        age_days = (now_naive - creation_naive).days
        return age_days
    except Exception as e:
        print(f"[Whois] Error fetching domain age: {e}")
        return None


def scan_url(url: str) -> dict:
    """
    Analyzes a URL for phishing, malware, and suspicious indicators.

    Checks performed:
      1. URL validity
      2. IP-based domain (high risk)
      3. Suspicious / abused TLDs
      4. Known URL shortener services
      5. Excessive subdomain chaining
      6. Typosquatting against trusted brands
      7. Phishing keywords in domain name
      8. Phishing / credential-harvesting keywords in path & query
      9. Non-HTTPS scheme on a page requesting sensitive info
     10. Homograph / punycode encoded domain

    Returns:
        dict: {url, risk_score (0-10), status, explanation, recommendation, sources}
    """
    risk_score = 0
    sources = []

    # --- Normalise URL ---
    url = url.strip()
    if not url:
        return _build_result(url, 0, "Safe", "No URL provided.", "Provide a URL to scan.", [])

    if not url.startswith(('http://', 'https://', 'ftp://')):
        url = 'http://' + url

    # --- Parse ---
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        path   = parsed.path.lower()
        query  = parsed.query.lower()
    except Exception:
        return _build_result(url, 10, "Malicious",
                             "The URL could not be parsed — it is malformed or uses an invalid format.",
                             "Do not interact with this link.", ["Malformed URL"])

    if not netloc:
        return _build_result(url, 10, "Malicious",
                             "The URL has no valid domain or host.",
                             "Do not interact with this link.", ["Missing Domain"])

    domain = _extract_base_domain(netloc)

    # ── Check 1: IP-based URL ──────────────────────────────────────────
    ip_pattern = re.compile(
        r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
    )
    if ip_pattern.match(domain):
        risk_score += 6
        sources.append("IP-based domain (direct IP instead of hostname)")

    # ── Check 2: Suspicious TLD ───────────────────────────────────────
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            risk_score += 3
            sources.append(f"Suspicious TLD ({tld})")
            break

    # ── Check 3: URL Shortener ────────────────────────────────────────
    if domain in URL_SHORTENERS:
        risk_score += 4
        sources.append("URL shortener detected — destination is hidden")

    # ── Check 4: Excessive Subdomains ─────────────────────────────────
    parts = domain.split('.')
    # A normal domain has 2–3 parts (e.g. sub.example.com)
    if len(parts) > 4:
        risk_score += 3
        sources.append(f"Excessive subdomains ({len(parts) - 2} levels deep)")

    # ── Check 5: Typosquatting / Brand impersonation in domain ────────
    found_brands = [b for b in TRUSTED_BRANDS if b in domain]
    if found_brands and not is_trusted_domain(domain):
        for brand in found_brands:
            risk_score += 4
            sources.append(f"Brand impersonation — '{brand}' found in domain")
            break  # one flag is enough

    # ── Check 6: Phishing keywords in domain name ─────────────────────
    domain_kw_hits = [kw for kw in PHISHING_DOMAIN_KEYWORDS if kw in domain]
    if domain_kw_hits:
        risk_score += 3
        sources.append(f"Suspicious keywords in domain: {', '.join(domain_kw_hits)}")

    # ── Check 7: Phishing keywords in path / query ────────────────────
    combined_path = path + '?' + query
    path_kw_hits = [kw for kw in PHISHING_PATH_KEYWORDS if kw in combined_path]
    if path_kw_hits:
        risk_score += 3
        sources.append(f"Sensitive keywords in URL path: {', '.join(path_kw_hits)}")

    # ── Check 8: HTTP (not HTTPS) with sensitive keywords ─────────────
    if parsed.scheme == 'http' and path_kw_hits and not is_trusted_domain(domain):
        risk_score += 2
        sources.append("Insecure HTTP scheme used on a page requesting sensitive data")

    # ── Check 9: Punycode / Homograph encoded domain ──────────────────
    if 'xn--' in domain:
        risk_score += 3
        sources.append("Punycode/homograph domain detected (possible visual spoofing)")

    # ── Check 10: Very long URL (obfuscation tactic) ──────────────────
    if len(url) > 200:
        risk_score += 1
        sources.append("Unusually long URL (obfuscation tactic)")

    # ── PHASE 4: OpenPhish Integration ──────────────────────────────
    if is_openphish_url(url):
        risk_score = 10
        sources.append("Known phishing URL (OpenPhish Community Feed)")

    # ── PHASE 3: Domain Age Analysis ────────────────────────────────
    domain_age_days = get_domain_age(domain)
    domain_age_str = "Unknown"
    
    if domain_age_days is not None:
        if domain_age_days > 365:
            years = domain_age_days // 365
            domain_age_str = f"{years} year{'s' if years > 1 else ''}"
        else:
            domain_age_str = f"{domain_age_days} days"
            
        if domain_age_days < 30:
            risk_score += 3
            sources.append(f"Domain is very new (created {domain_age_str} ago)")
        elif domain_age_days < 90:
            risk_score += 1
            sources.append(f"Domain is relatively new (created {domain_age_str} ago)")
        elif domain_age_days > 365:
            risk_score -= 1  # Reduce risk slightly for established domains

    # --- Clamp rule score to 0–10 ---
    rule_score = min(max(risk_score, 0), 10)
    
    if is_trusted_domain(domain):
        rule_score = min(rule_score, 2)
    
    # ── PHASE 1: AI URL Analysis (Cohere) ───────────────────────────
    ai_result = analyze_url_with_cohere(url)
    ai_powered = False
    ai_score = 0
    threat_type = "Unknown"
    ai_explanation = None
    ai_recommendation = None
    
    if ai_result:
        ai_powered = True
        ai_score = ai_result.get("risk_score", 0)
        threat_type = ai_result.get("threat_type", "Unknown")
        if "AI Analysis: " + ai_result.get("threat_type", "Unknown") not in sources:
             sources.append("AI Analyzed: " + ai_result.get("threat_type", "Unknown"))
        ai_explanation = ai_result.get("explanation")
        ai_recommendation = ai_result.get("recommendation")

    # Combine rule-engine score and AI score
    final_score = rule_score

    if ai_powered:
        if ai_score <= 2 and rule_score <= 5:
            final_score = min(rule_score, ai_score)
        elif ai_score >= 7 and rule_score >= 7:
            final_score = max(rule_score, ai_score)
        else:
            final_score = round((rule_score * 0.4) + (ai_score * 0.6))
            
    if is_trusted_domain(domain):
        final_score = min(final_score, 2)
        threat_type = "Safe"

    # ── PHASE 2: Confidence Score ───────────────────────────────────
    if is_openphish_url(url):
        confidence = 100
    elif ai_powered:
        if abs(rule_score - ai_score) <= 2:
            confidence = 85 + min(10, (10 - abs(rule_score - ai_score)))
        else:
            confidence = 60 + int((min(rule_score, ai_score) / 10) * 20)
    else:
        confidence = 60 + int((rule_score / 10) * 20)

    if final_score <= 3:
        confidence = max(60, min(confidence, 85))

    if domain_age_days is not None and domain_age_days < 30 and final_score >= 7:
        confidence = min(confidence + 5, 100)
        
    # Check intelligence cache
    intel = get_url_intelligence(domain)
    if intel and intel.get("times_seen", 0) > 5:
        confidence += 5

    # Enforce strict confidence ranges
    if is_openphish_url(url):
        confidence = 100
    else:
        if final_score >= 7:
            confidence = max(85, min(confidence, 99))
        elif final_score >= 4:
            confidence = max(70, min(confidence, 90))
        else:
            confidence = max(60, min(confidence, 85))

    # Update intelligence cache
    update_url_intelligence(domain, final_score, confidence)

    # --- Determine status & messages ---------
    if final_score >= 7:
        status = "Malicious"
        explanation = ai_explanation or (
            "This URL exhibits multiple high-risk indicators strongly associated with "
            "phishing, credential harvesting, or malware distribution. "
            f"Threat signals detected: {'; '.join(sources)}."
        )
        recommendation = ai_recommendation or (
            "Do NOT click or visit this link. Block the sender immediately. "
            "If you have already visited it, change your passwords and run a security scan."
        )
    elif final_score >= 4:
        status = "Suspicious"
        explanation = ai_explanation or (
            "This URL has characteristics commonly seen in malicious campaigns, "
            "although it may not be definitively malicious. "
            f"Signals detected: {'; '.join(sources)}."
        )
        recommendation = ai_recommendation or (
            "Proceed with extreme caution. Do not enter any personal information, "
            "credentials, or payment details. Verify the source independently."
        )
    else:
        status = "Safe"
        explanation = ai_explanation or (
            "No significant threat indicators were detected in the URL structure, domain, "
            "or path." + (f" Minor signals noted: {'; '.join(sources)}." if sources else "")
        )
        recommendation = ai_recommendation or (
            "The link appears generally safe, but always verify the sender "
            "and ensure the site uses HTTPS before entering any personal information."
        )
        threat_type = "Safe"

    return {
        "url": url,
        "risk_score": final_score,
        "status": status,
        "confidence": confidence,
        "explanation": explanation,
        "recommendation": recommendation,
        "threat_type": threat_type,
        "domain_age": domain_age_str,
        "ai_powered": ai_powered,
        "sources": sources
    }
