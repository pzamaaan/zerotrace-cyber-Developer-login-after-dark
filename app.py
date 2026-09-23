import os
import time
from datetime import datetime
from collections import deque
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
app.config['SECRET_KEY'] = 'login-after-dark-secret-key-2026'

# In-memory mock database of valid users
VALID_USERS = {
    "admin": "Secr3tP@ss!",
    "security_analyst": "Shield#2026",
    "alice": "CyberPass123",
    "bob": "NightOwl99!"
}

# Detection Configuration
OFF_HOURS_START = 23  # 11:00 PM
OFF_HOURS_END = 6     # 06:00 AM (ends at 06:00, so 23:00 - 05:59 is after dark)
BRUTE_FORCE_WINDOW_SECONDS = 180  # 3 minutes
BRUTE_FORCE_THRESHOLD = 3         # >= 3 failures in window
BURST_WINDOW_SECONDS = 10         # 10 seconds
BURST_THRESHOLD = 3               # >= 3 attempts in 10s is a rapid burst

# Audit Log and State Storage
# Each log entry: {
#   "id": int,
#   "timestamp": str,
#   "epoch": float,
#   "username": str,
#   "ip": str,
#   "auth_success": bool,
#   "risk_score": int,
#   "classification": "SAFE" | "SUSPICIOUS" | "CRITICAL",
#   "triggered_rules": list of dicts,
#   "details": str
# }
logs_store = deque(maxlen=200)
log_id_counter = 1

def evaluate_threat(username, ip, auth_success, attempt_time=None):
    """
    Evaluates authentication event against the 3 core security rules:
    Rule 1: Unusual Login Times ('After Dark' off-hours anomaly)
    Rule 2: Brute-Force & Repeated Failures
    Rule 3: Login Burst / Velocity Anomaly
    """
    now_epoch = time.time()
    dt = attempt_time if isinstance(attempt_time, datetime) else datetime.now()
    
    triggered_rules = []
    risk_score = 0

    # -------------------------------------------------------------
    # Feature 1: Unusual Login Times ("After Dark" Anomaly)
    # -------------------------------------------------------------
    hour = dt.hour
    is_after_dark = hour >= OFF_HOURS_START or hour < OFF_HOURS_END
    if is_after_dark:
        time_str = dt.strftime("%H:%M:%S")
        triggered_rules.append({
            "code": "UNUSUAL_HOURS",
            "name": "After-Dark Login Anomaly",
            "description": f"Authentication occurred at {time_str} during high-risk off-hours ({OFF_HOURS_START}:00 - {OFF_HOURS_END:02d}:00).",
            "severity": "MEDIUM",
            "weight": 35
        })
        risk_score += 35

    # -------------------------------------------------------------
    # Feature 2: Brute Force & Repeated Failed Attempts
    # -------------------------------------------------------------
    # Check failed attempts in sliding window for this username or IP
    recent_failures = [
        l for l in logs_store
        if (now_epoch - l["epoch"] <= BRUTE_FORCE_WINDOW_SECONDS)
        and not l["auth_success"]
        and (l["username"] == username or l["ip"] == ip)
    ]
    total_failures = len(recent_failures) + (1 if not auth_success else 0)

    if total_failures >= BRUTE_FORCE_THRESHOLD and not auth_success:
        triggered_rules.append({
            "code": "BRUTE_FORCE",
            "name": "Brute-Force Attack Pattern",
            "description": f"Repeated authentication failures ({total_failures} failures in past {BRUTE_FORCE_WINDOW_SECONDS}s). Potential credential guessing.",
            "severity": "HIGH",
            "weight": 50
        })
        risk_score += 50
    elif total_failures >= BRUTE_FORCE_THRESHOLD and auth_success:
        # Success after repeated failures indicates compromised account through brute force!
        triggered_rules.append({
            "code": "SUSPICIOUS_RECOVERY",
            "name": "Compromise After Brute-Force",
            "description": f"Successful login immediately following {len(recent_failures)} failed attempts within {BRUTE_FORCE_WINDOW_SECONDS}s.",
            "severity": "CRITICAL",
            "weight": 60
        })
        risk_score += 60

    # -------------------------------------------------------------
    # Feature 3: Login Burst / Velocity Anomaly
    # -------------------------------------------------------------
    # Check total attempts from IP in sliding window
    recent_attempts_from_ip = [
        l for l in logs_store
        if (now_epoch - l["epoch"] <= BURST_WINDOW_SECONDS) and (l["ip"] == ip)
    ]
    # Current attempt is +1
    burst_count = len(recent_attempts_from_ip) + 1

    if burst_count >= BURST_THRESHOLD:
        triggered_rules.append({
            "code": "BURST_VELOCITY",
            "name": "High-Velocity Burst Anomaly",
            "description": f"Abnormal burst of {burst_count} requests in {BURST_WINDOW_SECONDS}s from IP {ip}. Indicates automated tooling/script.",
            "severity": "HIGH",
            "weight": 40
        })
        risk_score += 40

    # Non-existent user penalty if failed
    if not auth_success and username not in VALID_USERS:
        risk_score += 15

    # Determine final threat classification
    risk_score = min(100, max(0, risk_score))
    if risk_score >= 65:
        classification = "CRITICAL"
    elif risk_score >= 30:
        classification = "SUSPICIOUS"
    else:
        classification = "SAFE"

    return risk_score, classification, triggered_rules


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/login", methods=["POST"])
def api_login():
    global log_id_counter
    data = request.get_json() or {}

    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    custom_ip = (data.get("ip") or "").strip()
    client_ip = custom_ip if custom_ip else (request.headers.get("X-Forwarded-For", request.remote_addr) or "127.0.0.1")
    simulated_hour = data.get("simulated_hour")  # e.g., 3 for 03:00 AM

    # Determine timestamp
    now = datetime.now()
    if simulated_hour is not None:
        try:
            hour_val = int(simulated_hour)
            attempt_time = now.replace(hour=hour_val, minute=18, second=42)
        except (ValueError, TypeError):
            attempt_time = now
    else:
        attempt_time = now

    # Verify credentials
    expected_password = VALID_USERS.get(username)
    auth_success = (expected_password is not None and expected_password == password)

    # Run detection engine
    risk_score, classification, triggered_rules = evaluate_threat(
        username=username,
        ip=client_ip,
        auth_success=auth_success,
        attempt_time=attempt_time
    )

    log_entry = {
        "id": log_id_counter,
        "timestamp": attempt_time.strftime("%Y-%m-%d %H:%M:%S"),
        "time_display": attempt_time.strftime("%H:%M:%S"),
        "epoch": time.time(),
        "username": username if username else "[empty]",
        "ip": client_ip,
        "auth_success": auth_success,
        "risk_score": risk_score,
        "classification": classification,
        "triggered_rules": triggered_rules,
        "details": f"Auth {'succeeded' if auth_success else 'failed'} for user '{username}' from {client_ip}."
    }
    log_id_counter += 1
    logs_store.appendleft(log_entry)

    response_data = {
        "status": "success" if auth_success else "failed",
        "message": "Authentication successful" if auth_success else "Invalid username or password",
        "evaluation": {
            "risk_score": risk_score,
            "classification": classification,
            "triggered_rules": triggered_rules,
            "timestamp": log_entry["timestamp"],
            "ip": client_ip,
            "username": username
        }
    }
    return jsonify(response_data), 200 if auth_success else 401


@app.route("/api/logs", methods=["GET"])
def api_logs():
    return jsonify(list(logs_store))


@app.route("/api/stats", methods=["GET"])
def api_stats():
    total_logs = len(logs_store)
    critical_count = sum(1 for l in logs_store if l["classification"] == "CRITICAL")
    suspicious_count = sum(1 for l in logs_store if l["classification"] == "SUSPICIOUS")
    safe_count = sum(1 for l in logs_store if l["classification"] == "SAFE")
    failed_auths = sum(1 for l in logs_store if not l["auth_success"])

    # Rule counts
    rule_counts = {
        "UNUSUAL_HOURS": 0,
        "BRUTE_FORCE": 0,
        "BURST_VELOCITY": 0,
        "SUSPICIOUS_RECOVERY": 0
    }
    for l in logs_store:
        for r in l.get("triggered_rules", []):
            code = r.get("code")
            if code in rule_counts:
                rule_counts[code] += 1

    return jsonify({
        "total_attempts": total_logs,
        "threats_detected": critical_count + suspicious_count,
        "critical_count": critical_count,
        "suspicious_count": suspicious_count,
        "safe_count": safe_count,
        "failed_auths": failed_auths,
        "rule_counts": rule_counts
    })


@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    """Generates attack or normal scenarios for instant demonstration."""
    data = request.get_json() or {}
    scenario = data.get("scenario")

    global log_id_counter

    if scenario == "after_dark":
        # Feature 1: Login at 03:15 AM
        now = datetime.now().replace(hour=3, minute=15, second=22)
        ip = "198.51.100.44"
        username = "admin"
        auth_success = True
        risk_score, classification, triggered_rules = evaluate_threat(
            username=username, ip=ip, auth_success=auth_success, attempt_time=now
        )
        entry = {
            "id": log_id_counter,
            "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
            "time_display": now.strftime("%H:%M:%S"),
            "epoch": time.time(),
            "username": username,
            "ip": ip,
            "auth_success": auth_success,
            "risk_score": risk_score,
            "classification": classification,
            "triggered_rules": triggered_rules,
            "details": f"Simulated off-hours login at 03:15 AM from {ip}."
        }
        log_id_counter += 1
        logs_store.appendleft(entry)
        return jsonify({"scenario": "after_dark", "entries_created": 1, "last_result": entry})

    elif scenario == "brute_force":
        # Feature 2: 4 repeated failed attempts from single IP/user
        ip = "203.0.113.88"
        user = "admin"
        entries = []
        passwords = ["123456", "admin123", "password", "welcome1"]
        for p in passwords:
            risk_score, classification, triggered_rules = evaluate_threat(
                username=user, ip=ip, auth_success=False, attempt_time=datetime.now()
            )
            entry = {
                "id": log_id_counter,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "time_display": datetime.now().strftime("%H:%M:%S"),
                "epoch": time.time(),
                "username": user,
                "ip": ip,
                "auth_success": False,
                "risk_score": risk_score,
                "classification": classification,
                "triggered_rules": triggered_rules,
                "details": f"Brute force attempt with password '{p}'."
            }
            log_id_counter += 1
            logs_store.appendleft(entry)
            entries.append(entry)
        return jsonify({"scenario": "brute_force", "entries_created": len(entries), "last_result": entries[-1]})

    elif scenario == "burst":
        # Feature 3: 5 requests within milliseconds from single IP
        ip = "192.0.2.77"
        entries = []
        for i in range(5):
            risk_score, classification, triggered_rules = evaluate_threat(
                username=f"bot_user_{i}", ip=ip, auth_success=False, attempt_time=datetime.now()
            )
            entry = {
                "id": log_id_counter,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "time_display": datetime.now().strftime("%H:%M:%S"),
                "epoch": time.time(),
                "username": f"bot_user_{i}",
                "ip": ip,
                "auth_success": False,
                "risk_score": risk_score,
                "classification": classification,
                "triggered_rules": triggered_rules,
                "details": f"Rapid velocity burst request #{i+1}."
            }
            log_id_counter += 1
            logs_store.appendleft(entry)
            entries.append(entry)
        return jsonify({"scenario": "burst", "entries_created": len(entries), "last_result": entries[-1]})

    elif scenario == "normal":
        # Normal daytime login
        now = datetime.now().replace(hour=14, minute=20, second=10)
        ip = "10.0.0.45"
        user = "alice"
        risk_score, classification, triggered_rules = evaluate_threat(
            username=user, ip=ip, auth_success=True, attempt_time=now
        )
        entry = {
            "id": log_id_counter,
            "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
            "time_display": now.strftime("%H:%M:%S"),
            "epoch": time.time(),
            "username": user,
            "ip": ip,
            "auth_success": True,
            "risk_score": risk_score,
            "classification": classification,
            "triggered_rules": triggered_rules,
            "details": f"Authorized normal daytime login by '{user}'."
        }
        log_id_counter += 1
        logs_store.appendleft(entry)
        return jsonify({"scenario": "normal", "entries_created": 1, "last_result": entry})

    return jsonify({"error": "Unknown scenario"}), 400


@app.route("/api/clear", methods=["POST"])
def api_clear():
    logs_store.clear()
    return jsonify({"status": "cleared", "total": 0})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
