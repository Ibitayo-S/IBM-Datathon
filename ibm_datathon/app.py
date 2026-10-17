from flask import Flask, request, jsonify, render_template
import time
import os

app = Flask(__name__)

# --- TELEMETRY ESTIMATOR ---
def estimate_network_telemetry(measured_latency_ms: float, measured_throughput_mbps: float) -> dict:
    """Estimates low-level Wi-Fi parameters from browser-measurable latency & throughput."""
    prev_delay = measured_latency_ms
    recent_avg_delay = measured_latency_ms * 1.02  # Slight variance for average

    # Baseline for clean Wi-Fi vs congested networks
    if measured_latency_ms < 50 and measured_throughput_mbps > 40:
        mac_retries = 0.1
        phy_drops = 0.01
        tx_duration = 1.2
    elif measured_latency_ms < 150 and measured_throughput_mbps > 15:
        mac_retries = 0.8
        phy_drops = 0.08
        tx_duration = 3.5
    else:
        mac_retries = 2.4
        phy_drops = 0.25
        tx_duration = 8.0

    return {
        "prev_auth_delay": round(prev_delay, 2),
        "recent_avg_auth_delay": round(recent_avg_delay, 2),
        "recent_mac_retry_indicator": round(mac_retries, 2),
        "recent_phy_drop_indicator": round(phy_drops, 2),
        "recent_observed_throughput": round(measured_throughput_mbps, 2),
        "recent_phy_tx_duration": round(tx_duration, 2),
    }

# --- ROUTES ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/ping', methods=['GET'])
def ping():
    """Lightweight endpoint to measure round-trip latency."""
    return jsonify({"status": "ok"})

@app.route('/api/payload-512k', methods=['GET'])
def payload():
    """Generates a 512KB payload for measuring throughput."""
    return os.urandom(512 * 1024)

@app.route('/api/estimate-telemetry', methods=['POST'])
def estimate_telemetry():
    data = request.json
    telemetry = estimate_network_telemetry(data['latency'], data['throughput'])
    return jsonify(telemetry)

@app.route('/api/predict', methods=['POST'])
def predict():
    """
    Receives network telemetry and scores candidate PQ configurations.
    In a real system, this loads latency_model.joblib and calls model.predict().
    """
    data = request.json
    telemetry = data.get('telemetry', {})
    
    # Mocking the ML prediction logic for demonstration
    base_latency = telemetry.get('recent_avg_auth_delay', 100)
    penalty_multiplier = 1 + (telemetry.get('recent_mac_retry_indicator', 0.1) * 0.5)

    configurations = [
        {"name": "ML-DSA-65", "base_cost": 25, "size_cost": 10},
        {"name": "ML-DSA-87", "base_cost": 40, "size_cost": 15},
        {"name": "SLH-DSA-SHA2-192f", "base_cost": 800, "size_cost": 20},
    ]

    results = []
    for config in configurations:
        # Simulated ridge regression equation:
        # predicted_delay = f(network_state, algorithm_compute, certificate_size)
        pred_latency = (base_latency + config['base_cost'] + (config['size_cost'] * penalty_multiplier))
        
        # 500ms threshold check
        status = "PASS" if pred_latency < 500 else "WARNING"
        
        results.append({
            "algorithm": config['name'],
            "predicted_ms": round(pred_latency, 1),
            "status": status
        })

    # Sort by lowest latency to simulate recommending the best acceptable configuration
    results.sort(key=lambda x: x['predicted_ms'])
    
    return jsonify({"predictions": results, "recommended": results[0]['algorithm']})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)