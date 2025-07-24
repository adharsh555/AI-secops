import time
from flask import Flask, request, jsonify
from input_analyzer import InputAnalyzer
from traffic_monitor import TrafficMonitor
from alert_system import AlertSystem

app = Flask(__name__)
input_checker = InputAnalyzer()
traffic_monitor = TrafficMonitor()
alert_system = AlertSystem()

# Mock AI API (replace with a real model or service in production)
def ai_api(prompt):
    return {"response": f"Processed: {prompt}"}

@app.route('/api/predict', methods=['POST'])
def predict():
    client_ip = request.remote_addr
    data = request.json
    prompt = data.get('prompt', '')  # <-- Ensure you're sending "prompt" in JSON

    print(f"[DEBUG] Prompt received: {prompt}")
    print(f"[DEBUG] From IP: {client_ip}")

    # 1. Check traffic patterns
    traffic_monitor.log_request(client_ip, time.time())
    if traffic_monitor.is_abnormal(client_ip):
        alert_system.quarantine(request, "Abnormal traffic pattern")
        return jsonify({"error": "Request blocked (traffic pattern)"}), 403

    # 2. Analyze input content
    if input_checker.is_malicious(prompt):
        alert_system.quarantine(request, "Malicious input detected")
        return jsonify({"error": "Request blocked (malicious input)"}), 403

    # 3. Process with AI model
    response = ai_api(prompt)

    # 4. (Optional) Analyze AI output
    # if output_checker.is_sensitive(response):
    #     alert_system.quarantine(request, "Sensitive output detected")

    return jsonify(response)

# Optional root route for visibility/testing
@app.route('/')
def index():
    return "🛡️ AI-SecOps Firewall is running.", 200

if __name__ == '__main__':
    # Using adhoc SSL for testing; not for production
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')
