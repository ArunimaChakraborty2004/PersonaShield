# 🛡️ PersonaShield
**Making cybersecurity human.**
PersonaShield is a real-time social engineering detection system that goes beyond traditional threat flagging. Designed with empathy and explainability at its core, it helps users understand what's risky, why it’s flagged, and how to respond turning complex message analysis into a conversation.
##  Features
- **Threat Scoring & Type Detection**  
  Flags manipulation tactics like urgency, secrecy, impersonation, and information theft.
- **Explainability Panels**  
  Shows matched keywords and trigger phrases for every flagged message.
- **Interactive Dashboard**  
  Displays threat type frequency, user feedback, and search filtering by message content.
- **Quick Replies & Typing Indicator**  
  Chat-like interface that feels intuitive and responsive.
##  Tech Stack

- **Frontend:** HTML, CSS (Tailwind), JavaScript  
- **Backend:** Python Flask (REST API)  
- **Database:** MongoDB  
- **Visualization:** Chart.js  
- **Security Concepts:** Social engineering patterns, NLP scoring, explainable AI
##  File Structure Overview

\`\`\`plaintext
├── index.html            # Chat interface  
├── dashboard.html        # Threat logs + analytics  
├── style.css             # Styling and UI elements  
├── app.js                # Frontend threat logic  
├── dashboard.js          # Chart & table rendering  
├── app.py                # Flask API backend  
├── db.py                 # MongoDB interactions  
├── threat_detector.py    # NLP-based scoring model  
├── avatar.png            # Bot display image  
└── README.md             # Project documentation  
\`\`\`

##  Getting Started

# Clone the repository
git clone https://github.com/ArunimaChakraborty2004/PersonaShield

# Set up Python virtual environment
python -m venv env
source env/bin/activate

# Install backend dependencies
pip install -r requirements.txt

# Run Flask server
python app.py

Ensure MongoDB is running locally or on a hosted service. Open index.html in a browser and test with sample messages to see live threat detection.

Sample Messages & Scores
plaintext
"Please confirm your password and upload the credentials."
→ Score: 8 | Type: Info Theft

"This is your final call. Respond ASAP to avoid account lockout."
→ Score: 9 | Type: Urgency

"Don't tell anyone. Keep this confidential."
→ Score: 7 | Type: Secrecy
##  Future Scope

-  Gemini/LLM-based tone detection with confidence scoring  
-  Chrome extension for browser-based real-time scanning  
-  Multi-language support (English, Hindi, Turkish)  
-  Threat timeline storytelling across users  
-  Adaptive feedback-based tuning engine

## Author
Crafted with clarity & care by Arunima Chakraborty  BTech CSE, Christ University Cybersecurity Enthusiast

“It’s not just about detecting threats it’s about helping users understand them.” — PersonaShield
