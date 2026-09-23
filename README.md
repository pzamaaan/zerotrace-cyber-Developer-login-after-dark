# Login After Dark 🌙🛡️

A real-time suspicious authentication activity detection and log analysis system built with **Python Flask**.

The interface features an atmospheric cyber-defense dark theme with a **two-panel split layout**:
- **Left Panel**: Real-time SOC Security Operations Dashboard (KPI counters, active rule stats, 1-click attack simulators, and live streaming audit log).
- **Right Panel**: Interactive Authentication Portal (with customizable credentials, IP override, simulated time hours, and instant risk assessment verdict).

---

## 3 Core Detection Features

1. **Unusual Login Times ("After Dark" Anomaly)**:
   - Evaluates authentication timestamps against baseline operational hours.
   - Detects and flags logins occurring during high-risk off-hours (**11:00 PM – 06:00 AM**).
2. **Brute-Force & Repeated Failures Detection**:
   - Tracks failed login attempts within a sliding time window (3 minutes).
   - Flags an alert when **&ge; 3 failed attempts** occur for a targeted username or client IP.
   - Escalates to `CRITICAL` if a successful login occurs immediately following a brute-force wave (potential compromised account).
3. **Login Bursts / Velocity Anomaly**:
   - Monitors the velocity of incoming authentication requests per IP.
   - Flags rapid bursts (**&ge; 3 attempts in < 10 seconds**), distinguishing automated credential-stuffing bots and scripts from humans.

---

## Quickstart

### 1. Prerequisites & Virtual Environment
```bash
cd /home/hrushi/.gemini/antigravity/scratch/login-after-dark
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Run the Application
```bash
python app.py
```
Then open `http://127.0.0.1:5000` in your web browser.

### 3. Run Automated Tests
```bash
python -m unittest test_app.py
```

---

## Testing Scenarios

You can test using the interactive form on the right or the 1-click simulation buttons on the left:

- **🌙 Test "After Dark"**: Simulates a login attempt at 03:15 AM.
- **⚔️ Test Brute-Force**: Fires 4 consecutive failed logins against user `admin`.
- **⚡ Test Rapid Burst**: Fires 5 rapid requests within milliseconds from a single IP.
- **✅ Test Safe Login**: Normal daytime login during standard business hours.

### Valid Credentials for Manual Login:
- `admin` / `Secr3tP@ss!`
- `alice` / `CyberPass123`
- `bob` / `NightOwl99!`
