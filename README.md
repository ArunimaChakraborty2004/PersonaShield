# 🛡️ PersonaShield

## AI-Powered Social Engineering & Phishing Detection Platform

PersonaShield is a real-time cybersecurity application that detects phishing attempts, social engineering attacks, impersonation, credential theft, urgency manipulation, and other digital threats.

Unlike traditional keyword-based filters, PersonaShield combines AI-powered contextual analysis with an explainable threat detection engine, helping users understand not only what is dangerous, but why it is dangerous and how to respond safely.

---

## 🚀 Live Features

### 🤖 AI-Powered Threat Detection

Uses Cohere AI to analyze message context and identify phishing, impersonation, information theft, secrecy tactics, and social engineering patterns.

### 🛡️ Rule-Based Fallback Engine

Continues detecting threats even if AI services are unavailable, ensuring reliability and uninterrupted protection.

### 📊 Risk Scoring System

Assigns threat scores from 0–10 and categorizes messages by severity:

* Safe
* Low Risk
* Medium Risk
* High Risk
* Critical Risk

### 🔍 Explainable Security Analysis

Provides detailed explanations for every detection, including:

* Threat category
* Matched keywords
* Trigger phrases
* AI-generated reasoning
* Recommended actions

### 📈 Threat Intelligence Dashboard

Monitor and analyze:

* Threat frequency
* Risk score distribution
* Historical threat logs
* Threat type statistics
* Search and filtering

### 💾 Threat Log Management

Stores all analysis results in MongoDB for auditing, analytics, and future review.

### ☁️ Cloud Deployment

Deployed on Render with MongoDB integration and environment-based secret management.

---

## 🛠️ Technology Stack

### Frontend

* HTML5
* CSS3
* Tailwind CSS
* JavaScript

### Backend

* Python
* Flask
* REST APIs

### AI & Security

* Cohere AI
* Social Engineering Detection Engine
* Explainable Threat Analysis
* Risk Scoring Framework

### Database

* MongoDB

### Visualization

* Chart.js

### Deployment

* Render

---

## 📂 Project Structure

```text
PersonaShield/
│
├── app.py                  # Flask API Backend
├── ai_analyzer.py          # Cohere AI Analysis Engine
├── threat_detector.py      # Rule-Based Threat Detection
├── db.py                   # MongoDB Integration
│
├── index.html              # User Chat Interface
├── dashboard.html          # Threat Analytics Dashboard
│
├── app.js                  # Frontend Logic
├── dashboard.js            # Dashboard Rendering
├── style.css               # Styling
│
├── requirements.txt
├── runtime.txt
├── README.md
│
└── assets/
```

## 🔎 Example Threat Analysis

### Message

```text
Urgent action required! Our security team detected suspicious activity on your account. Verify your identity immediately and upload your login credentials using the secure link below. Do not tell anyone about this investigation.
```

### Detection Result

```json
{
  "score": 7,
  "severity": "high",
  "threat_type": "Phishing",
  "ai_powered": true
}
```

### AI Explanation

The message creates urgency and fear by claiming suspicious account activity. It requests sensitive information and instructs the recipient to keep the interaction secret, which are common characteristics of phishing and social engineering attacks.

---

## 🎯 Key Capabilities

✔ Phishing Detection

✔ Credential Theft Detection

✔ Impersonation Detection

✔ Urgency Manipulation Detection

✔ Secrecy-Based Social Engineering Detection

✔ Explainable AI Analysis

✔ Real-Time Threat Monitoring

✔ Cloud Deployment

✔ MongoDB Threat Logging

---

## 🔮 Future Enhancements

* URL Reputation Analysis
* VirusTotal Integration
* AbuseIPDB Integration
* Threat Intelligence Feed Aggregation
* Browser Extension
* Email Threat Scanning
* Multi-Language Detection
* User Authentication & Roles
* PDF Threat Reports
* Adaptive Threat Learning

---

## 👨‍💻 Author

Arunima Chakraborty

B.Tech Computer Science & Engineering

Cybersecurity & AI Enthusiast

---

"Cybersecurity is not only about detecting threats — it's about helping people understand and respond to them."
