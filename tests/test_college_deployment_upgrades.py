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
2. Complete Removal of QR Stickers (/print-qr-stickers):
   - Confirms endpoint returns 404 and qr_stickers.html is deleted
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
        self.csrf_token = "mepco_test_csrf_token"
        with self.client.session_transaction() as sess:
            sess["user"] = {
                "id": 1,
                "username": "admin",
                "full_name": "System Administrator",
                "role": "admin",
                "email": "admin@mepcoeng.ac.in"
            }
            sess["csrf_token"] = self.csrf_token

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

    def test_02_qr_stickers_endpoint_removed(self):
        """Verify /print-qr-stickers has been completely removed and returns 404."""
        res = self.client.get("/print-qr-stickers")
        self.assertEqual(res.status_code, 404)
        filepath = os.path.join(BASE_DIR, "templates", "qr_stickers.html")
        self.assertFalse(os.path.exists(filepath))

    def test_05_nba_naac_register_api_json(self):
        """Verify NBA / NAAC Equipment Down-Time & Maintenance Register JSON API."""
        res = self.client.get("/api/reports/nba-naac-register")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("Mepco Schlenk Engineering College", data["institution"])
        self.assertIn("Department of Artificial Intelligence and Data Science", data["department"])
        self.assertIn("NBA Criterion 6", data["accreditation"])
        self.assertIsInstance(data["records"], list)
        self.assertGreater(data["total_incidents"], 0)
        self.assertIn("mean_time_to_repair_minutes", data)

    def test_06_nba_naac_register_api_csv(self):
        """Verify NBA / NAAC Equipment Maintenance Register CSV export format."""
        res = self.client.get("/api/reports/nba-naac-register?format=csv")
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.content_type.startswith("text/csv"))
        csv_text = res.get_data(as_text=True)
        self.assertIn("Entry Code", csv_text)
        self.assertIn("Ticket Number", csv_text)
        self.assertIn("Laboratory Room", csv_text)
        self.assertIn("Downtime Duration", csv_text)

    def test_07_nba_naac_register_html_page(self):
        """Verify printable NBA / NAAC Register HTML page renders institutional elements."""
        res = self.client.get("/admin/reports/nba-naac-register")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn("Mepco Schlenk Engineering College", html)
        self.assertIn("Department of Artificial Intelligence and Data Science", html)
        self.assertIn("National Board of Accreditation", html)
        self.assertIn("Signature of Head of Department", html)

    def test_08_database_backup_api(self):
        """Verify zero-downtime online SQLite database snapshotting."""
        res = self.client.post("/api/admin/database/backup", json={"prefix": "test"}, headers={"X-CSRFToken": self.csrf_token})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertTrue(os.path.exists(data.get("path")))
        self.assertGreater(data.get("size_bytes", 0), 1000)

        # Verify listing
        res_list = self.client.get("/api/admin/database/backups")
        self.assertEqual(res_list.status_code, 200)
        backups_data = res_list.get_json()
        self.assertGreaterEqual(backups_data.get("count", 0), 1)

    def test_09_telegram_config_api(self):
        """Verify Telegram Bot configuration endpoints."""
        res = self.client.get("/api/admin/telegram/config")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("configured", data)

        # Validation check: missing fields should reject with 400
        res_invalid = self.client.post("/api/admin/telegram/save", json={"bot_token": ""}, headers={"X-CSRFToken": self.csrf_token})
        self.assertEqual(res_invalid.status_code, 400)

    def test_10_quick_fault_chips_in_report_html(self):
        """Verify 1-Click Fast Reporting Quick-Select chips exist in templates/report.html."""
        res = self.client.get("/report")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn("quick-fault-chips", html)
        self.assertIn("quickFillFault", html)
        self.assertIn("[CUDA GPU OOM]", html)
        self.assertIn("[System Frozen / BSOD]", html)
        self.assertIn("[No Display]", html)

    def test_11_zero_emojis_in_nba_naac_register_template(self):
        """Verify zero emojis in templates/nba_naac_register.html."""
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

        filepath = os.path.join(BASE_DIR, "templates", "nba_naac_register.html")
        self.assertTrue(os.path.exists(filepath))
        with open(filepath, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f, 1):
                emojis = [c for c in line if is_emoji(c)]
                self.assertEqual(len(emojis), 0, f"Found emoji in nba_naac_register.html at line {idx}: {emojis}")


if __name__ == "__main__":
    unittest.main()
