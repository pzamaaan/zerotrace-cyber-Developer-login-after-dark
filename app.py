"""
ZeroTrace - Login After Dark
Authentication Monitoring & Threat Intelligence Dashboard
"""

import random
from flask import Flask, render_template, request

app = Flask(__name__)


def get_mock_context(active_page="overview"):
    random.seed(7)
    hourly_activity = [round(random.uniform(0.05, 0.30), 2) for _ in range(24)]
    # 2am and 3am spikes -> unusual off-hours "Login After Dark" login activity
    hourly_activity[2] = 0.84
    hourly_activity[3] = 0.92
    
    hourly_counts = [random.randint(8, 35) for _ in range(24)]
    hourly_counts[2] = 68
    hourly_counts[3] = 81

    return {
        "active_page": active_page,
        "window_label": "last 24h",
        "stats": {
            "total_logins": 4821,
            "failed_attempts": 312,
            "active_alerts": 4,
            "blocked_ips": 6,
            "failed_delta": 18,
            "blocked_delta": 2,
            "risk_score": 64,
        },
        "hourly_activity": hourly_activity,
        "hourly_counts": hourly_counts,
        "suspicious_ips": [
            {
                "ip": "185.220.101.4",
                "country": "Tor Exit Node",
                "country_code": "TOR",
                "attempts": 47,
                "reason": "Credential stuffing pattern",
                "risk": "High"
            },
            {
                "ip": "45.155.204.12",
                "country": "Romania (RO)",
                "country_code": "RO",
                "attempts": 33,
                "reason": "Brute force against admin",
                "risk": "High"
            },
            {
                "ip": "103.98.63.221",
                "country": "Vietnam (VN)",
                "country_code": "VN",
                "attempts": 21,
                "reason": "Off-hours burst, new device fingerprint",
                "risk": "Medium"
            },
            {
                "ip": "91.240.118.82",
                "country": "Netherlands (NL)",
                "country_code": "NL",
                "attempts": 16,
                "reason": "Unrecognized ASN / VPN endpoint",
                "risk": "Medium"
            },
        ],
        "alerts": [
            {
                "time": "03:14:02",
                "user": "j.romero",
                "ip": "185.220.101.4",
                "level": "critical",
                "reason": "12 failed attempts in 90s (off-hours)",
                "status": "Investigating"
            },
            {
                "time": "02:58:41",
                "user": "admin",
                "ip": "45.155.204.12",
                "level": "critical",
                "reason": "Automated brute-force targeting root credentials",
                "status": "Blocked"
            },
            {
                "time": "02:22:15",
                "user": "m.vasquez",
                "ip": "194.26.29.11",
                "level": "suspicious",
                "reason": "Simultaneous logins from two distant geographic locations",
                "status": "Flagged"
            },
            {
                "time": "22:41:10",
                "user": "s.iyer",
                "ip": "103.98.63.221",
                "level": "suspicious",
                "reason": "Login from unrecognized country & browser agent",
                "status": "Challenged"
            },
            {
                "time": "21:02:55",
                "user": "d.chen",
                "ip": "70.31.44.9",
                "level": "normal",
                "reason": "Successful MFA login, known corporate workstation",
                "status": "Resolved"
            },
        ],
        "bruteforce_users": [
            {"user": "admin", "attempts": 9, "threshold": 10, "state": "imminent"},
            {"user": "j.romero", "attempts": 7, "threshold": 10, "state": "elevated"},
            {"user": "m.vasquez", "attempts": 5, "threshold": 10, "state": "moderate"},
            {"user": "s.iyer", "attempts": 3, "threshold": 10, "state": "normal"},
        ],
    }


@app.route("/")
@app.route("/dashboard")
def dashboard():
    return render_template("index.html", **get_mock_context("overview"))


@app.route("/alerts")
def alerts_page():
    return render_template("index.html", **get_mock_context("alerts"))


@app.route("/watchlist")
def watchlist_page():
    return render_template("index.html", **get_mock_context("watchlist"))


@app.route("/users")
def users_page():
    return render_template("index.html", **get_mock_context("users"))


@app.route("/about")
def about():
    context = get_mock_context("about")
    return render_template("about.html", **context)


@app.route("/contact")
def contact():
    context = get_mock_context("contact")
    return render_template("contact.html", **context)


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)