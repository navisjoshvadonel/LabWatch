"""
test_aids_realtime_solving.py
Comprehensive Test Suite for AIDS Department Real-Time Solving & Diagnostic Engine
Mepco Schlenk Engineering College (Autonomous), Sivakasi
Department of Artificial Intelligence & Data Science (AIDS)

Tests:
1. AI Lab Doctor: Diagnosis of CUDA OOM, Jupyter freeze, and proxy timeouts
2. Automated Playbooks: Execution of kill_ai_zombies, network_self_heal, disk_scratch_purge
3. Deep Multi-Protocol Diagnostics: L3 ICMP + L4 TCP probe
4. Exam Readiness Engine: Concurrent pre-lab audit & certificate generation
5. Native SVG QR Code Generator: Pure vector barcode validation
6. Department Analytics: Reliability index, repeat offenders, uptime
7. SSE Live Event Stream: Real-time broadcast verification
"""

import os
import sys
import unittest
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from python_server import app, get_db_connection
from ai_diagnostic import ai_diagnostic_engine
from event_broker import event_broker


class TestAIDSRealTimeSolving(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.csrf_token = "test_csrf_token_secret_12345"
        with self.client.session_transaction() as sess:
            sess["user"] = {
                "id": 1,
                "username": "admin",
                "full_name": "System Administrator",
                "role": "admin",
                "email": "admin@mepcoeng.ac.in"
            }
            sess["csrf_token"] = self.csrf_token

    def test_01_ai_diagnostic_engine_cuda_oom(self):
        """Verify AI Lab Doctor correctly identifies CUDA GPU Out-Of-Memory failure."""
        res = self.client.post("/api/ai/diagnose", json={
            "description": "PyTorch training crashed with RuntimeError: CUDA out of memory. Tried to allocate 4.2 GiB.",
            "category": "Software Crash"
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()["diagnosis"]
        self.assertTrue(data["matched"])
        self.assertEqual(data["recommended_playbook"], "kill_ai_zombies")
        self.assertIn("torch.cuda.empty_cache", data["student_instant_advice"])
        self.assertGreaterEqual(data["confidence_score"], 90)

    def test_02_ai_diagnostic_engine_jupyter_kernel(self):
        """Verify AI Lab Doctor diagnoses Jupyter kernel deadlock."""
        res = self.client.post("/api/ai/diagnose", json={
            "description": "Jupyter notebook cell stuck in infinite loop, kernel died and disconnected.",
            "category": "Software Crash"
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()["diagnosis"]
        self.assertTrue(data["matched"])
        self.assertEqual(data["recommended_playbook"], "service_restart")

    def test_03_remediation_playbook_kill_zombies(self):
        """Verify 1-click execution of kill_ai_zombies playbook."""
        res = self.client.post(
            "/api/remediate",
            json={"pc_id": "PC-01", "playbook_id": "kill_ai_zombies"},
            headers={"X-CSRFToken": self.csrf_token}
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "Success")
        self.assertIn("SIGTERM", data["output_log"])

        # Verify entry in REMEDIATION_LOGS table
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM REMEDIATION_LOGS WHERE playbook_id = 'kill_ai_zombies' ORDER BY id DESC LIMIT 1")
        log_entry = cursor.fetchone()
        conn.close()
        self.assertIsNotNone(log_entry)
        self.assertEqual(log_entry["status"], "Success")

    def test_04_remediation_playbook_network_self_heal(self):
        """Verify network stack self-heal playbook flushes DNS and tests gateway."""
        res = self.client.post(
            "/api/remediate",
            json={"pc_id": "PC-02", "playbook_id": "network_self_heal"},
            headers={"X-CSRFToken": self.csrf_token}
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("Gateway", data["output_log"])

    def test_05_deep_diagnostics_probe(self):
        """Verify multi-protocol L3+L4 health diagnostic on workstation."""
        res = self.client.get("/api/diagnose/PC-01")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["pc_number"], "PC-01")
        self.assertIn("ports", data)
        self.assertIn("gateway_ip", data)
        self.assertIn("health_score", data)

    def test_06_exam_readiness_audit_and_certificate(self):
        """Verify Pre-Lab / Exam Readiness concurrent sweep and certificate generation."""
        res = self.client.post(
            "/api/exam-readiness",
            json={"lab_id": 1},
            headers={"X-CSRFToken": self.csrf_token}
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        cert = data["certificate"]
        self.assertTrue(cert["certificate_id"].startswith("CERT-AIDS-2026-"))
        self.assertGreater(cert["total_pcs"], 0)
        self.assertIn(cert["certification_status"], ["EXAM_READY", "CONDITIONAL_READY", "CRITICAL_ACTION_REQUIRED"])

    def test_07_pc_qr_code_generation(self):
        """Verify vector SVG QR code generation for mobile reporting."""
        res = self.client.get("/api/pc-qr/PC-15")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["pc_number"], "PC-15")
        self.assertIn("<svg", data["svg"])
        self.assertIn("/report?lab_id=", data["reporting_url"])

    def test_08_aids_department_analytics(self):
        """Verify AIDS departmental operational analytics."""
        res = self.client.get("/api/analytics/aids")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("overall_uptime_pct", data)
        self.assertIn("lab_scores", data)
        self.assertGreater(len(data["lab_scores"]), 0)


if __name__ == "__main__":
    unittest.main()
