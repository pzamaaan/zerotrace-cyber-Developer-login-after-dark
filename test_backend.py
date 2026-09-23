"""
ZeroTrace - Login After Dark
Automated Backend & Detection Engine Test Suite
"""

import unittest
from datetime import datetime, timezone, timedelta
from app import app, db
from models import AuthLog, Alert, WatchlistIP
from detector import ThreatDetector


class TestLoginAfterDarkBackend(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        self.app = app
        self.client = app.test_client()

        with app.app_context():
            db.create_all()
            self.detector = ThreatDetector(lockout_threshold=10)

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_01_normal_login(self):
        """Pattern: Normal legitimate authentication should be classified as NORMAL with low risk."""
        with app.app_context():
            now = datetime.now(timezone.utc).replace(hour=14, minute=30)  # Daytime
            res = self.detector.analyze_event({
                "user": "alice",
                "ip": "192.0.2.50",
                "status": "SUCCESS",
                "country": "United States",
                "timestamp": now
            })
            self.assertEqual(res["classification"], "NORMAL")
            self.assertLess(res["risk_score"], 35.0)
            self.assertIsNone(res["alert"])

    def test_02_unusual_login_time_after_dark(self):
        """Pattern: Unusual Login Times ('Login After Dark' 00:00 - 05:00 UTC)."""
        with app.app_context():
            now = datetime.now(timezone.utc).replace(hour=3, minute=15)  # 03:15 AM Nocturnal
            res = self.detector.analyze_event({
                "user": "night.shift",
                "ip": "203.0.113.10",
                "status": "FAILURE",
                "country": "Germany",
                "timestamp": now
            })
            patterns = " ".join(res["triggered_patterns"]).lower()
            self.assertTrue("unusual login time" in patterns or "nocturnal" in patterns)
            self.assertGreaterEqual(res["risk_score"], 35.0)
            self.assertIn(res["classification"], ["SUSPICIOUS", "CRITICAL"])

    def test_03_login_burst(self):
        """Pattern: Login Burst (>= 5 rapid attempts in 60s)."""
        with app.app_context():
            now = datetime.now(timezone.utc).replace(hour=14, minute=0)
            for i in range(5):
                t = now - timedelta(seconds=(5 - i) * 5)
                db.session.add(AuthLog(
                    user="finance_user",
                    ip="198.51.100.22",
                    status="FAILURE",
                    timestamp=t,
                    country="United States"
                ))
            db.session.commit()

            # 6th attempt within the 60s window
            res = self.detector.analyze_event({
                "user": "finance_user",
                "ip": "198.51.100.22",
                "status": "FAILURE",
                "timestamp": now
            })
            patterns = " ".join(res["triggered_patterns"]).lower()
            self.assertIn("login burst", patterns)

    def test_04_suspicious_ip_detection(self):
        """Pattern: Suspicious IP Addresses (Tor Exit Nodes & Known Threats)."""
        with app.app_context():
            now = datetime.now(timezone.utc).replace(hour=15, minute=0)
            res = self.detector.analyze_event({
                "user": "bob",
                "ip": "185.220.101.4",  # Known Tor exit
                "status": "FAILURE",
                "country": "Tor Network",
                "timestamp": now
            })
            patterns = " ".join(res["triggered_patterns"]).lower()
            self.assertIn("suspicious ip", patterns)
            self.assertGreaterEqual(res["risk_score"], 50.0)

    def test_05_brute_force_lockout_threshold(self):
        """Pattern: Potential Brute-Force Behavior (approaching account lockout)."""
        with app.app_context():
            now = datetime.now(timezone.utc).replace(hour=11, minute=0)
            # Simulate 7 prior failures on admin
            for i in range(7):
                t = now - timedelta(minutes=1, seconds=i * 5)
                db.session.add(AuthLog(
                    user="admin",
                    ip="203.0.113.88",
                    status="FAILURE",
                    timestamp=t,
                    country="France"
                ))
            db.session.commit()

            # 8th failure
            res = self.detector.analyze_event({
                "user": "admin",
                "ip": "203.0.113.88",
                "status": "FAILURE",
                "timestamp": now
            })
            patterns = " ".join(res["triggered_patterns"]).lower()
            self.assertIn("brute-force", patterns)
            self.assertEqual(res["classification"], "CRITICAL")
            self.assertIsNotNone(res["alert"])

    def test_06_credential_stuffing(self):
        """Pattern: Abnormal Pattern A — Distributed Credential Stuffing (1 IP targeting multiple users)."""
        with app.app_context():
            now = datetime.now(timezone.utc).replace(hour=16, minute=0)
            stuffing_ip = "198.51.100.77"
            target_accounts = ["user1", "user2", "user3"]
            for idx, u in enumerate(target_accounts):
                db.session.add(AuthLog(
                    user=u,
                    ip=stuffing_ip,
                    status="FAILURE",
                    timestamp=now - timedelta(minutes=idx + 1)
                ))
            db.session.commit()

            # Next attempt from same IP against a 4th account
            res = self.detector.analyze_event({
                "user": "user4",
                "ip": stuffing_ip,
                "status": "FAILURE",
                "timestamp": now
            })
            patterns = " ".join(res["triggered_patterns"]).lower()
            self.assertIn("credential stuffing", patterns)

    def test_07_impossible_travel(self):
        """Pattern: Abnormal Pattern B — Impossible Travel Velocity."""
        with app.app_context():
            now = datetime.now(timezone.utc).replace(hour=16, minute=0)
            # Prior successful login from US 30 minutes ago
            db.session.add(AuthLog(
                user="globetrotter",
                ip="70.31.44.9",
                status="SUCCESS",
                country="United States",
                timestamp=now - timedelta(minutes=30)
            ))
            db.session.commit()

            # Subsequent login attempt from Vietnam 30 mins later
            res = self.detector.analyze_event({
                "user": "globetrotter",
                "ip": "103.98.63.221",
                "status": "FAILURE",
                "country": "Vietnam",
                "timestamp": now
            })
            patterns = " ".join(res["triggered_patterns"]).lower()
            self.assertIn("impossible travel", patterns)

    def test_08_api_endpoints(self):
        """Verify REST API Ingest, Logs, Alerts, Watchlist, and Stats."""
        # 1. Ingest event via POST /api/ingest
        res = self.client.post("/api/ingest", json={
            "user": "api_test_user",
            "ip": "198.51.100.99",
            "status": "FAILURE",
            "country": "Canada"
        })
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("risk_score", data["analysis"])

        # 2. Query logs via GET /api/logs
        res = self.client.get("/api/logs?user=api_test_user")
        self.assertEqual(res.status_code, 200)
        logs_data = res.get_json()
        self.assertGreaterEqual(logs_data["count"], 1)

        # 3. Query stats via GET /api/stats
        res = self.client.get("/api/stats")
        self.assertEqual(res.status_code, 200)
        stats_data = res.get_json()
        self.assertIn("stats", stats_data)
        self.assertIn("hourly_activity", stats_data)
        self.assertEqual(len(stats_data["hourly_activity"]), 24)

        # 4. Trigger simulation via POST /api/simulate
        res = self.client.post("/api/simulate?scenario=burst")
        self.assertEqual(res.status_code, 200)
        sim_data = res.get_json()
        self.assertEqual(sim_data["scenario"], "burst")
        self.assertGreater(sim_data["events_generated"], 0)

    def test_09_html_dashboard_routes(self):
        """Verify web pages render HTTP 200 with live SQLite data."""
        for path in ["/", "/dashboard", "/alerts", "/watchlist", "/users", "/about", "/contact"]:
            res = self.client.get(path)
            self.assertEqual(res.status_code, 200, f"Failed route: {path}")


if __name__ == "__main__":
    unittest.main()

