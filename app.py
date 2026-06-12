from dotenv import load_dotenv
load_dotenv("En.env")

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from ai_analyzer import analyze_message
from url_scanner import scan_url
from db import save_message, update_feedback, messages, save_url_scan, url_logs
from bson import ObjectId
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

# ─── Static File Serving ───────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/dashboard')
def dashboard():
    return send_from_directory('.', 'dashboard.html')

@app.route('/scanner')
def scanner():
    return send_from_directory('.', 'scanner.html')

@app.route('/url_scanner')
def url_scanner():
    return send_from_directory('.', 'url_scanner.html')

@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory('.', filename)


# ─── Core: Detect & Save ──────────────────────────────────────────
@app.route('/api/detect_threat', methods=['POST'])
def detect():
    data = request.get_json()
    message = data.get('message', '')
    result = analyze_message(message)

    save_message(
        text=message,
        score=result["score"],
        threat_type=result["threat_type"],
        matched_keywords=result.get("matched_keywords", []),
        matched_phrases=result.get("matched_phrases", []),
        severity=result.get("severity", "safe"),
        explanation=result.get("explanation", ""),
        recommendation=result.get("recommendation", ""),
        ai_powered=result.get("ai_powered", False)
    )
    return jsonify(result)


# ─── Bulk Scan ────────────────────────────────────────────────────
@app.route('/api/bulk_scan', methods=['POST'])
def bulk_scan():
    data = request.get_json()
    text = data.get('text', '')
    if not text.strip():
        return jsonify({"error": "No text provided"}), 400

    # Split into sentences
    import re
    sentences = [s.strip() for s in re.split(r'(?<=[.!?])\s+', text) if s.strip()]

    findings = []
    overall_score = 0

    for sentence in sentences:
        result = analyze_message(sentence)
        if result["score"] > 0:
            findings.append({
                "sentence": sentence,
                "score": result["score"],
                "type": result["threat_type"],
                "severity": result.get("severity", "safe"),
                "explanation": result.get("explanation", "")
            })
            overall_score = max(overall_score, result["score"])

    return jsonify({
        "overall_score": overall_score,
        "total_sentences": len(sentences),
        "threat_count": len(findings),
        "findings": findings
    })


# ─── Fetch Logs ───────────────────────────────────────────────────
@app.route('/api/logs')
def get_logs():
    try:
        limit = int(request.args.get('limit', 100))
        skip  = int(request.args.get('skip', 0))
        data = list(messages.find({}, {
            "text": 1, "score": 1, "threat_type": 1,
            "timestamp": 1, "feedback": 1,
            "matched_keywords": 1, "matched_phrases": 1,
            "severity": 1, "explanation": 1, "recommendation": 1,
            "ai_powered": 1
        }).sort("timestamp", -1).skip(skip).limit(limit))
        for entry in data:
            entry["_id"] = str(entry["_id"])
            if "timestamp" in entry and entry["timestamp"]:
                entry["timestamp"] = entry["timestamp"].isoformat()
        return jsonify(data)
    except Exception as e:
        print("Error fetching logs:", e)
        return jsonify([]), 500


# ─── Dashboard Summary ────────────────────────────────────────────
@app.route('/api/summary')
def summary():
    try:
        total = messages.count_documents({})
        threats = messages.count_documents({"score": {"$gt": 4}})
        safe = messages.count_documents({"score": {"$lte": 4}})

        avg_pipeline = [{"$group": {"_id": None, "avg": {"$avg": "$score"}}}]
        avg_result = list(messages.aggregate(avg_pipeline))
        avg_score = round(avg_result[0]["avg"], 1) if avg_result else 0

        return jsonify({
            "total": total,
            "threats": threats,
            "safe": safe,
            "avg_score": avg_score
        })
    except Exception as e:
        print("Summary error:", e)
        return jsonify({"total": 0, "threats": 0, "safe": 0, "avg_score": 0})


# ─── Stats for Chart ─────────────────────────────────────────────
@app.route('/api/stats')
def threat_stats():
    pipeline = [
        {"$group": {"_id": "$threat_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    result = list(messages.aggregate(pipeline))
    return jsonify(result)


# ─── Timeline Stats ───────────────────────────────────────────────
@app.route('/api/timeline')
def timeline():
    try:
        days = int(request.args.get('days', 7))
        pipeline = [
            {"$match": {"timestamp": {"$gte": datetime.utcnow() - timedelta(days=days)}}},
            {"$group": {
                "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
                "count": {"$sum": 1},
                "threats": {"$sum": {"$cond": [{"$gt": ["$score", 4]}, 1, 0]}}
            }},
            {"$sort": {"_id": 1}}
        ]
        result = list(messages.aggregate(pipeline))
        return jsonify(result)
    except Exception as e:
        print("Timeline error:", e)
        return jsonify([])


# ─── Search Logs ──────────────────────────────────────────────────
@app.route('/api/search')
def search_logs():
    keyword = request.args.get("q", "")
    query = {"text": {"$regex": keyword, "$options": "i"}} if keyword else {}
    try:
        data = list(messages.find(query, {
            "text": 1, "score": 1, "threat_type": 1, "timestamp": 1,
            "feedback": 1, "matched_keywords": 1, "matched_phrases": 1,
            "severity": 1, "explanation": 1, "ai_powered": 1
        }).sort("timestamp", -1).limit(100))
        for entry in data:
            entry["_id"] = str(entry["_id"])
            if "timestamp" in entry and entry["timestamp"]:
                entry["timestamp"] = entry["timestamp"].isoformat()
        return jsonify(data)
    except Exception as e:
        print("Search error:", e)
        return jsonify([]), 500


# ─── Feedback ─────────────────────────────────────────────────────
@app.route('/api/feedback/<entry_id>', methods=['POST'])
def feedback(entry_id):
    value = request.get_json().get('feedback')
    update_feedback(ObjectId(entry_id), value)
    return jsonify({"status": "updated"})


# ─── Test ─────────────────────────────────────────────────────────
@app.route('/api/test')
def test_trigger():
    message = "Urgent! Please confirm your password and upload credentials immediately."
    result = analyze_message(message)
    return jsonify(result)


# ─── URL Scanner Endpoints ──────────────────────────────────────────
@app.route('/api/scan_url', methods=['POST'])
def api_scan_url():
    data = request.get_json()
    url = data.get('url', '')
    if not url.strip():
        return jsonify({"error": "No URL provided"}), 400
        
    result = scan_url(url)
    save_url_scan(
        url=result["url"],
        risk_score=result["risk_score"],
        status=result["status"],
        explanation=result["explanation"],
        recommendation=result["recommendation"],
        sources=result.get("sources", []),
        confidence=result.get("confidence", 0),
        threat_type=result.get("threat_type", "Unknown"),
        domain_age=result.get("domain_age", None),
        ai_powered=result.get("ai_powered", False)
    )
    return jsonify(result)

@app.route('/api/url_summary')
def url_summary():
    try:
        total = url_logs.count_documents({})
        threats = url_logs.count_documents({"status": "Malicious"})
        suspicious = url_logs.count_documents({"status": "Suspicious"})
        safe = url_logs.count_documents({"status": "Safe"})
        return jsonify({
            "total": total,
            "malicious": threats,
            "suspicious": suspicious,
            "threats": threats + suspicious,
            "safe": safe
        })
    except Exception as e:
        print("URL Summary error:", e)
        return jsonify({"total": 0, "malicious": 0, "suspicious": 0, "threats": 0, "safe": 0})

@app.route('/api/url_logs')
def get_url_logs():
    try:
        limit = int(request.args.get('limit', 10))
        data = list(url_logs.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit))
        for entry in data:
            if "timestamp" in entry and entry["timestamp"]:
                entry["timestamp"] = entry["timestamp"].isoformat()
        return jsonify(data)
    except Exception as e:
        print("URL Logs error:", e)
        return jsonify([]), 500

@app.route('/api/url_stats')
def get_url_stats():
    try:
        # Threat Distribution
        dist_pipeline = [
            {"$group": {"_id": "$threat_type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        threat_dist = list(url_logs.aggregate(dist_pipeline))
        
        # Risk Score Trends (last 7 days)
        days = 7
        trend_pipeline = [
            {"$match": {"timestamp": {"$gte": datetime.utcnow() - timedelta(days=days)}}},
            {"$group": {
                "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
                "avg_risk": {"$avg": "$risk_score"},
                "scans": {"$sum": 1}
            }},
            {"$sort": {"_id": 1}}
        ]
        risk_trends = list(url_logs.aggregate(trend_pipeline))
        
        # Top Suspicious Domains
        domain_pipeline = [
            {"$match": {"status": {"$in": ["Suspicious", "Malicious"]}}},
            {"$group": {
                "_id": "$url", 
                "count": {"$sum": 1},
                "avg_risk": {"$avg": "$risk_score"}
            }},
            {"$sort": {"count": -1}},
            {"$limit": 5}
        ]
        top_domains = list(url_logs.aggregate(domain_pipeline))
        
        return jsonify({
            "threat_distribution": threat_dist,
            "risk_trends": risk_trends,
            "top_domains": top_domains
        })
    except Exception as e:
        print("URL Stats error:", e)
        return jsonify({
            "threat_distribution": [],
            "risk_trends": [],
            "top_domains": []
        }), 500

# ─── Launch ───────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
