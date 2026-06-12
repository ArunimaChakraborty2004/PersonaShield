import os
from dotenv import load_dotenv

# Ensure environment is loaded before anything else
load_dotenv('En.env')

from url_scanner import scan_url

test_cases = [
    # Safe
    "https://google.com",
    "https://github.com",
    "https://openai.com",
    "https://amazon.com",
    
    # Suspicious
    "https://support-google.com",
    "https://verify-google-account.com",
    
    # Malicious
    "https://google-login-security.xyz/login",
    "https://paypal-account-verify.top/auth"
]

print("--- SCANNER TEST CASES ---")
for url in test_cases:
    print(f"\nScanning: {url}")
    result = scan_url(url)
    print(f"Status: {result.get('status')}")
    print(f"Score: {result.get('risk_score')}")
    print(f"Confidence: {result.get('confidence')}%")
    print(f"Sources: {result.get('sources')}")
    print(f"AI Powered: {result.get('ai_powered')}")
    print(f"Threat Type: {result.get('threat_type')}")
