"""
test_zero_phone_college_reporting.py
Zero-Phone College Lab Reporting Verification Suite
Mepco Schlenk Engineering College (Autonomous), Sivakasi
Department of Artificial Intelligence & Data Science (AIDS)

Validates:
1. Workstation Auto-Detection API (/api/client/auto-detect): Resolves client IP to workstation & lab.
2. Reporting with Roll/Register Number (e.g. 22AD042): Institutional accountability.
3. Master Podium 1-Tap Physical Fault Reporting: Quick-ticket creation via pc_number without manual lab lookup.
"""

import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from python_server import app, get_db_connection


class TestZeroPhoneCollegeReporting(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.csrf_token = "mepco_zero_phone_test_2026"
        with self.client.session_transaction() as sess:
            sess["user"] = {
                "id": 2,
                "username": "navis",
                "full_name": "Navis Joshva",
                "role": "student",
                "email": "navis@mepcoeng.ac.in"
            }
            sess["csrf_token"] = self.csrf_token

    def test_01_auto_detect_api_by_ip(self):
        """Verify client IP is automatically resolved to exact workstation and laboratory."""
        res = self.client.get("/api/client/auto-detect?ip=192.168.1.118")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("detected"))
        comp = data.get("computer")
        self.assertIsNotNone(comp)
        self.assertEqual(comp.get("pc_number"), "PC-18")
        self.assertEqual(comp.get("lab_name"), "Deep Learning Lab")

    def test_02_auto_detect_api_by_pc_param(self):
        """Verify workstation parameter correctly auto-resolves for demo/testing."""
        res = self.client.get("/api/client/auto-detect?pc=PC-30")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("detected"))
        self.assertEqual(data.get("computer", {}).get("pc_number"), "PC-30")

    def test_03_ticket_submission_with_roll_number(self):
        """Verify ticket submission captures student register number for attendance/accountability."""
        res = self.client.post("/report", json={
            "lab_id": 1,
            "pc_number": "PC-18",
            "roll_number": "22AD042",
            "issue_category": "Software Crash",
            "description": "PyTorch CUDA Out-Of-Memory during batch training",
            "priority": "High"
        }, headers={"X-CSRFToken": self.csrf_token})

        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        tck = data.get("ticket")
        self.assertIn("22AD042", tck.get("reporter", ""))
        self.assertIn("22AD042", tck.get("description", ""))

    def test_04_podium_quick_ticket_by_pc_number(self):
        """Verify technician/podium console can log hardware faults with only pc_number."""
        with self.client.session_transaction() as sess:
            sess["user"] = {
                "id": 1,
                "username": "admin",
                "full_name": "System Administrator",
                "role": "admin"
            }
            sess["csrf_token"] = self.csrf_token

        res = self.client.post("/api/tickets", json={
            "pc_number": "PC-15",
            "issue_category": "Peripheral / Display",
            "description": "[Podium Staff Quick-Report]: Mouse / Keyboard Fault - Left click stuck",
            "priority": "Medium"
        }, headers={"X-CSRFToken": self.csrf_token})

        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("ticket", {}).get("pc_number"), "PC-15")


if __name__ == "__main__":
    unittest.main()
