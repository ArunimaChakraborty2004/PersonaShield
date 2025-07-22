from flask import Flask, request, jsonify
from flask_cors import CORS
from threat_detector import detect_threat_json
from db import save_message, update_feedback, messages
from bson import ObjectId

app = Flask(__name__)
CORS(app)

# ✅ Detect threat and save full explainability
@app.route('/api/detect_threat', methods=['POST'])
def detect():
    data = request.get_json()
    message = data.get('message', '')
    result = detect_threat_json(message)
    # Ensure threat_type is present for frontend
    result["threat_type"] = result.get("type", "")
    save_message(
        text=message,
        score=result["score"],
        threat_type=result["threat_type"],
        matched_keywords=result.get("matched_keywords", []),
        matched_phrases=result.get("matched_phrases", [])
    )
    
    return jsonify(result)

# ✅ Fetch all logs from database
@app.route('/api/logs')
def get_logs():
    try:
        data = list(messages.find({}, {
            "text": 1,
            "score": 1,
            "threat_type": 1,
            "timestamp": 1,
            "feedback": 1,
            "matched_keywords": 1,
            "matched_phrases": 1
        }))
        for entry in data:
            entry["_id"] = str(entry["_id"])
        return jsonify(data)
    except Exception as e:
        print("Error fetching logs:", e)
        return jsonify([]), 500

# ✅ Submit feedback for a specific log
@app.route('/api/feedback/<entry_id>', methods=['POST'])
def feedback(entry_id):
    value = request.get_json().get('feedback')
    update_feedback(ObjectId(entry_id), value)
    return jsonify({ "status": "updated" })

# ✅ Get threat statistics (aggregated)
@app.route('/api/stats')
def threat_stats():
    pipeline = [
        { "$group": { "_id": "$threat_type", "count": { "$sum": 1 } } },
        { "$sort": { "count": -1 } }
    ]
    result = list(messages.aggregate(pipeline))
    return jsonify(result)

# ✅ Search logs by keyword (text match)
@app.route('/api/search')
def search_logs():
    keyword = request.args.get("q", "")
    query = { "text": { "$regex": keyword, "$options": "i" } } if keyword else {}
    try:
        data = list(messages.find(query, {
            "text": 1,
            "score": 1,
            "threat_type": 1,
            "timestamp": 1,
            "feedback": 1,
            "matched_keywords": 1,
            "matched_phrases": 1
        }))
        for entry in data:
            entry["_id"] = str(entry["_id"])
        return jsonify(data)
    except Exception as e:
        print("Error searching logs:", e)
        return jsonify([]), 500

# ✅ Analyze single message for testing (optional)
@app.route('/api/analyze', methods=['POST'])
def analyze_message():
    data = request.get_json()
    message = data.get("text", "")
    result = detect_threat_json(message)
    print("DEBUG:", result)
    return jsonify(result)

# ✅ Test sample message directly via GET
@app.route('/api/test', methods=['GET'])
def test_trigger_response():
    message = "Please confirm your password and upload the credentials"
    result = detect_threat_json(message)
    print("TRIGGER TEST RESULT:", result)
    return jsonify(result)

# ✅ Launch server
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
