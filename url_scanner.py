import re
from urllib.parse import urlparse

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
    'bank', 'wellsfargo', 'chase', 'citibank', 'hsbc', 'barclays'
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
    'support', 'helpdesk', 'service', 'paypal', 'amazon', 'microsoft',
    'apple', 'google', 'bank', 'signin'
]


def _extract_base_domain(netloc: str) -> str:
    """Strip port and return only the hostname."""
    return netloc.split(':')[0]


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
    # Only flag if the domain is NOT actually the brand's own domain
    for brand in found_brands:
        if not (domain == f'{brand}.com' or domain == f'www.{brand}.com'):
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
    if parsed.scheme == 'http' and (domain_kw_hits or path_kw_hits):
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

    # --- Clamp to 0–10 ---
    risk_score = min(risk_score, 10)

    # --- Determine status & messages ---------
    if risk_score >= 7:
        status = "Malicious"
        explanation = (
            "This URL exhibits multiple high-risk indicators strongly associated with "
            "phishing, credential harvesting, or malware distribution. "
            f"Threat signals detected: {'; '.join(sources)}."
        )
        recommendation = (
            "Do NOT click or visit this link. Block the sender immediately. "
            "If you have already visited it, change your passwords and run a security scan."
        )
    elif risk_score >= 4:
        status = "Suspicious"
        explanation = (
            "This URL has characteristics commonly seen in malicious campaigns, "
            "although it may not be definitively malicious. "
            f"Signals detected: {'; '.join(sources)}."
        )
        recommendation = (
            "Proceed with extreme caution. Do not enter any personal information, "
            "credentials, or payment details. Verify the source independently."
        )
    else:
        status = "Safe"
        explanation = (
            "No significant threat indicators were detected in the URL structure, domain, "
            "or path." + (f" Minor signals noted: {'; '.join(sources)}." if sources else "")
        )
        recommendation = (
            "The link appears generally safe, but always verify the sender "
            "and ensure the site uses HTTPS before entering any personal information."
        )

    return _build_result(url, risk_score, status, explanation, recommendation, sources)


def _build_result(url, risk_score, status, explanation, recommendation, sources):
    """Construct the standard scan result dictionary."""
    return {
        "url": url,
        "risk_score": risk_score,
        "status": status,
        "explanation": explanation,
        "recommendation": recommendation,
        "sources": sources
    }
