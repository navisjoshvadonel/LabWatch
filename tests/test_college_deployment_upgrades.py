"""
test_college_deployment_upgrades.py
College-Level Institutional Deployment Verification Suite
Mepco Schlenk Engineering College (Autonomous), Sivakasi
Department of Artificial Intelligence & Data Science (AIDS)

Validates:
1. Production Deployment Posture API (/api/deployment/status):
   - Mepco Schlenk Engineering College institutional metadata
   - Database WAL mode & PRAGMA integrity_check
   - Multi-interface LAN IPv4 address enumeration
   - 246 Workstations & 6 Labs verification
2. Workstation Physical QR Sticker Sheet (/print-qr-stickers):
   - Renders valid SVG QR codes for all 246 workstations
   - Supports filtered lab view (e.g. ?lab_id=1 for Deep Learning Lab)
   - Zero emojis compliance across qr_stickers.html template
"""

import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from python_server import app


class TestCollegeDeploymentUpgrades(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_01_deployment_status_api(self):
        """Verify deployment status API returns institutional metadata and integrity."""
        res = self.client.get("/api/deployment/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertIn("Mepco Schlenk Engineering College", data["institution"])
        self.assertIn("Artificial Intelligence and Data Science", data["department"])
        self.assertEqual(data["deployment_posture"], "College Production Grade")

        # Verify Data Tier
        dt = data["data_tier"]
        self.assertEqual(dt["journal_mode"], "WAL")
        self.assertEqual(dt["integrity_check"].lower(), "ok")
        self.assertEqual(dt["total_laboratories"], 6)
        self.assertEqual(dt["total_workstations"], 246)

        # Verify Network & Host Environment
        he = data["host_environment"]
        self.assertIsInstance(he["active_lan_ips"], list)
        self.assertEqual(he["bound_port"], 5000)

    def test_02_print_qr_stickers_all_labs(self):
        """Verify bulk workstation physical sticker generator renders HTML with vector SVGs."""
        res = self.client.get("/print-qr-stickers")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)

        self.assertIn("Mepco Schlenk Engineering College", html)
        self.assertIn("Artificial Intelligence", html)
        self.assertIn("PC-01", html)
        self.assertIn("Deep Learning Lab", html)
        self.assertIn("<svg", html)
        self.assertIn("Scan with Phone to Report Issue", html)

    def test_03_print_qr_stickers_filtered_lab(self):
        """Verify single lab QR sticker generation."""
        res = self.client.get("/print-qr-stickers?lab_id=1")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)

        self.assertIn("Deep Learning Lab", html)
        self.assertIn("<svg", html)

    def test_04_zero_emojis_in_qr_stickers_template(self):
        """Verify zero emojis in templates/qr_stickers.html."""
        def is_emoji(ch):
            cp = ord(ch)
            return (
                (0x1F300 <= cp <= 0x1FAFF) or
                (0x1F600 <= cp <= 0x1F64F) or
                (0x1F680 <= cp <= 0x1F6FF) or
                (0x2600 <= cp <= 0x27BF) or
                (0x2300 <= cp <= 0x23FF) or
                (0x2B50 <= cp <= 0x2B55)
            )

        filepath = os.path.join(BASE_DIR, "templates", "qr_stickers.html")
        self.assertTrue(os.path.exists(filepath))
        with open(filepath, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f, 1):
                emojis = [c for c in line if is_emoji(c)]
                self.assertEqual(len(emojis), 0, f"Found emoji in qr_stickers.html at line {idx}: {emojis}")


if __name__ == "__main__":
    unittest.main()
