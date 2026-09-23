import unittest
from datetime import datetime
from app import app, logs_store

class LoginAfterDarkTestCase(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        logs_store.clear()

    def test_feature1_after_dark_anomaly(self):
        """Feature 1: Off-hours login (03:00 AM) triggers UNUSUAL_HOURS rule."""
        res = self.client.post("/api/login", json={
            "username": "admin",
            "password": "Secr3tP@ss!",
            "simulated_hour": 3,
            "ip": "10.1.1.20"
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        eval_data = data["evaluation"]
        rule_codes = [r["code"] for r in eval_data["triggered_rules"]]
        self.assertIn("UNUSUAL_HOURS", rule_codes)
        self.assertEqual(eval_data["classification"], "SUSPICIOUS")

    def test_feature2_brute_force_detection(self):
        """Feature 2: >= 3 repeated failures triggers BRUTE_FORCE rule."""
        ip = "192.168.1.99"
        for _ in range(2):
            self.client.post("/api/login", json={
                "username": "admin",
                "password": "WrongPassword!",
                "ip": ip,
                "simulated_hour": 14
            })

        res = self.client.post("/api/login", json={
            "username": "admin",
            "password": "WrongPassword!",
            "ip": ip,
            "simulated_hour": 14
        })
        self.assertEqual(res.status_code, 401)
        data = res.get_json()
        eval_data = data["evaluation"]
        rule_codes = [r["code"] for r in eval_data["triggered_rules"]]
        self.assertIn("BRUTE_FORCE", rule_codes)
        self.assertEqual(eval_data["classification"], "CRITICAL")

    def test_feature3_burst_velocity_anomaly(self):
        """Feature 3: >= 3 rapid requests from single IP triggers BURST_VELOCITY."""
        ip = "172.16.0.4"
        for _ in range(2):
            self.client.post("/api/login", json={
                "username": "alice",
                "password": "CyberPass123",
                "ip": ip,
                "simulated_hour": 14
            })

        res = self.client.post("/api/login", json={
            "username": "alice",
            "password": "CyberPass123",
            "ip": ip,
            "simulated_hour": 14
        })
        data = res.get_json()
        eval_data = data["evaluation"]
        rule_codes = [r["code"] for r in eval_data["triggered_rules"]]
        self.assertIn("BURST_VELOCITY", rule_codes)

    def test_normal_daytime_login(self):
        """Normal daytime login with correct credentials should be SAFE."""
        res = self.client.post("/api/login", json={
            "username": "alice",
            "password": "CyberPass123",
            "simulated_hour": 14,
            "ip": "10.0.0.88"
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        eval_data = data["evaluation"]
        self.assertEqual(eval_data["classification"], "SAFE")
        self.assertEqual(len(eval_data["triggered_rules"]), 0)

    def test_simulation_endpoints(self):
        """Test preset simulation triggers."""
        res = self.client.post("/api/simulate", json={"scenario": "after_dark"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["scenario"], "after_dark")

        res_stats = self.client.get("/api/stats")
        self.assertEqual(res_stats.status_code, 200)
        stats = res_stats.get_json()
        self.assertEqual(stats["total_attempts"], 1)

if __name__ == "__main__":
    unittest.main()