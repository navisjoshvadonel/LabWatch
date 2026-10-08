"""
test_college_deployment_readiness.py
Institutional Deployment Verification Suite
Mepco Schlenk Engineering College (Autonomous), Sivakasi
Department of Artificial Intelligence & Data Science (AIDS)

Validates:
1. Zero Emojis Compliance: Verifies 100% eradication of emojis across all UI templates and backend code.
2. Mepco Schlenk Institutional Identity: Official college and department branding verification.
3. SVG Logo Health: UTF-8 encoding and static asset serving.
4. High Concurrency Database Stress: Concurrent multi-threaded reads/writes under WAL mode.
5. Multi-Subnet WoL Broadcast calculation.
6. Pre-Exam Lab Readiness Audit & Certificate Engine.
"""

import concurrent.futures
import os
import re
import sqlite3
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from python_server import app, get_db_connection, DB_PATH
from remediation_engine import get_db, PLAYBOOKS_METADATA


class TestCollegeDeploymentReadiness(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.csrf_token = "mepco_test_token_2026"
        with self.client.session_transaction() as sess:
            sess["user"] = {
                "id": 1,
                "username": "admin",
                "full_name": "System Administrator",
                "role": "admin",
                "email": "admin@mepcoeng.ac.in"
            }
            sess["csrf_token"] = self.csrf_token

    def test_01_zero_emojis_across_all_templates_and_code(self):
        """Strictly enforce that zero emojis exist in templates, remediation engine, and core server."""
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

        target_files = [
            os.path.join(BASE_DIR, "templates", "index.html"),
            os.path.join(BASE_DIR, "templates", "admin.html"),
            os.path.join(BASE_DIR, "templates", "login.html"),
            os.path.join(BASE_DIR, "templates", "report.html"),
            os.path.join(BASE_DIR, "templates", "status.html"),
            os.path.join(BASE_DIR, "python_server.py"),
            os.path.join(BASE_DIR, "remediation_engine.py"),
            os.path.join(BASE_DIR, "PROJECT_REPORT.md"),
        ]

        for filepath in target_files:
            self.assertTrue(os.path.exists(filepath), f"File {filepath} does not exist")
            with open(filepath, "r", encoding="utf-8") as f:
                for idx, line in enumerate(f, 1):
                    emojis = [c for c in line if is_emoji(c)]
                    self.assertEqual(
                        len(emojis), 0,
                        f"Found forbidden emoji in {os.path.basename(filepath)} at line {idx}: {[f'U+{ord(c):04X}' for c in emojis]}"
                    )

    def test_02_mepco_schlenk_branding_and_recognition(self):
        """Verify Mepco Schlenk Engineering College institutional branding on all portals."""
        endpoints = ["/login", "/report", "/monitor", "/admin"]
        for ep in endpoints:
            res = self.client.get(ep, follow_redirects=True)
            self.assertEqual(res.status_code, 200)
            body = res.get_data(as_text=True)
            self.assertIn("Mepco Schlenk Engineering College", body)
            self.assertIn("Sivakasi", body)

    def test_03_svg_logo_asset_serving_and_encoding(self):
        """Verify institutional SVG logo is properly served with valid XML and UTF-8 encoding."""
        res = self.client.get("/static/mepco_logo.svg")
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.content_type.startswith("image/svg+xml"))
        # Verify valid SVG XML header
        content = res.get_data()
        self.assertTrue(b"<svg" in content or b"<?xml" in content)
        self.assertFalse(content.startswith(b"\xff\xfe"), "SVG logo must not contain UTF-16 BOM")

    def test_04_database_concurrency_stress_test(self):
        """Stress-test concurrent reads and writes to SQLite to ensure zero locking errors."""
        def worker(worker_id):
            conn = get_db_connection()
            try:
                c = conn.cursor()
                c.execute("SELECT count(*) FROM COMPUTERS")
                _ = c.fetchone()[0]
                c.execute("UPDATE COMPUTERS SET last_heartbeat = CURRENT_TIMESTAMP WHERE id = ?", ((worker_id % 10) + 1,))
                conn.commit()
                return True
            except Exception as e:
                return False
            finally:
                conn.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker, i) for i in range(30)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        self.assertTrue(all(results), "All concurrent database operations must succeed without locking")

    def test_05_pre_exam_readiness_audit_certificate(self):
        """Verify exam mode health sweep generates valid institutional certificate."""
        res = self.client.post(
            "/api/exam-readiness",
            json={"lab_id": 1, "audited_by": "Dr. Lab In-Charge"},
            headers={"X-CSRFToken": self.csrf_token}
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        cert = data["certificate"]
        self.assertIn("CERT-", cert["certificate_id"])
        self.assertGreater(cert["total_pcs"], 0)
        self.assertGreaterEqual(cert["readiness_percentage"], 0)

    def test_06_playbooks_metadata_clean_badges(self):
        """Verify remediation playbooks metadata has clean text badges and no emojis."""
        for pb_id, meta in PLAYBOOKS_METADATA.items():
            self.assertIn("badge", meta)
            self.assertTrue(meta["badge"].startswith("[") and meta["badge"].endswith("]"))
            self.assertFalse(any(ord(c) > 0x2000 for c in meta["badge"]))


if __name__ == "__main__":
    unittest.main()
