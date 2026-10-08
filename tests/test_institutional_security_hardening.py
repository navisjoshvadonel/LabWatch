"""
test_institutional_security_hardening.py
Verification suite for enterprise/institutional security hardening:
1. Machine-to-Machine (M2M) C Daemon Mutual Authentication (X-Daemon-Token)
2. Zero-Trust RBAC Privilege Enforcement on Remote Actions (/api/restart, /api/remediate, /api/exam-readiness)
3. Insecure Direct Object Reference (IDOR) Immunity on Ticket Creation
4. Student Ticket Privacy Isolation
5. SOC Security Status & Dynamic Admin Lockout Override API
"""

import os
import sys
import unittest
import json
import secrets

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from python_server import (
    app,
    get_db_connection,
    rate_limiter,
    DAEMON_SECRET_TOKEN,
)


class TestInstitutionalSecurityHardening(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.csrf_token = "test_csrf_token_security_suite_2026"

    def test_01_m2m_c_daemon_authentication_rejection(self):
        """Verify unauthorized LAN devices cannot spoof telemetry without X-Daemon-Token."""
        # Unauthenticated request with no token -> 401 Unauthorized
        res = self.client.post("/api/pc-status", json={
            "pc_id": "PC-01",
            "status": "online"
        })
        self.assertEqual(res.status_code, 401)
        data = res.get_json()
        self.assertIn("Machine-to-machine authentication required", data["error"])

        # Forged or invalid token -> 401 Unauthorized
        res_bad = self.client.post("/api/pc-status", json={
            "pc_id": "PC-01",
            "status": "online"
        }, headers={"X-Daemon-Token": "forged_malicious_token_123"})
        self.assertEqual(res_bad.status_code, 401)

    def test_02_m2m_c_daemon_authentication_success(self):
        """Verify legitimate C daemon presenting correct token is authenticated successfully."""
        res = self.client.post("/api/pc-status", json={
            "pc_id": "PC-01",
            "status": "online",
            "ip_address": "192.168.1.1",
            "mac_address": "AA:BB:CC:DD:EE:01"
        }, headers={"X-Daemon-Token": DAEMON_SECRET_TOKEN})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["pc_id"], "PC-01")

    def test_03_zero_trust_remote_restart_enforcement(self):
        """Verify /api/restart requires Admin/Technician privileges (Zero-Trust RBAC)."""
        # 1. Unauthenticated -> 401 Unauthorized or 403 CSRF rejected
        res_anon = self.client.post("/api/restart", json={"pc_id": "PC-01"}, headers={"X-CSRFToken": self.csrf_token})
        self.assertIn(res_anon.status_code, (401, 403))

        # 2. Student Role -> 403 Forbidden
        with self.client.session_transaction() as sess:
            sess["user"] = {"id": 2, "username": "navis", "role": "student"}
            sess["csrf_token"] = self.csrf_token
        res_student = self.client.post("/api/restart", json={"pc_id": "PC-01"}, headers={"X-CSRFToken": self.csrf_token})
        self.assertEqual(res_student.status_code, 403)

        # 3. Admin Role -> Authorized (reaches execution)
        with self.client.session_transaction() as sess:
            sess["user"] = {"id": 1, "username": "admin", "role": "admin"}
            sess["csrf_token"] = self.csrf_token
        res_admin = self.client.post("/api/restart", json={"pc_id": "PC-01"}, headers={"X-CSRFToken": self.csrf_token})
        self.assertIn(res_admin.status_code, (200, 500))  # 200 if WoL dispatched, 500 if socket unavailable in test env, but NOT 401/403

    def test_04_zero_trust_remediate_enforcement(self):
        """Verify /api/remediate is locked against unauthorized callers."""
        # Unauthenticated -> 401 or 403
        res_anon = self.client.post("/api/remediate", json={"pc_id": "PC-01", "playbook_id": "network_self_heal"})
        self.assertIn(res_anon.status_code, (401, 403))

        # Student -> 403
        with self.client.session_transaction() as sess:
            sess["user"] = {"id": 2, "username": "navis", "role": "student"}
            sess["csrf_token"] = self.csrf_token
        res_student = self.client.post("/api/remediate", json={
            "pc_id": "PC-01",
            "playbook_id": "network_self_heal"
        }, headers={"X-CSRFToken": self.csrf_token})
        self.assertEqual(res_student.status_code, 403)

    def test_05_idor_protection_ticket_creation(self):
        """Verify tickets cannot be forged under another user's ID (Identity Spoofing Immunity)."""
        student_id = 2  # Navis Joshva
        target_spoofed_id = 1  # Attacker tries to frame Admin (ID 1)

        with self.client.session_transaction() as sess:
            sess["user"] = {"id": student_id, "username": "navis", "role": "student"}
            sess["csrf_token"] = self.csrf_token

        res = self.client.post("/api/tickets", json={
            "user_id": target_spoofed_id,  # Spoofing attempt
            "lab_id": 1,
            "computer_id": 1,
            "issue_category": "Software Crash",
            "description": "Jupyter kernel died during deep learning training",
            "priority": "Medium"
        }, headers={"X-CSRFToken": self.csrf_token})

        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        ticket_number = data["ticket"]["ticket_number"]

        # Check DB: Reporter user_id MUST be Navis (2), NOT spoofed Admin (1)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM TICKETS WHERE ticket_number = ?", (ticket_number,))
        row = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row["user_id"], student_id)
        self.assertNotEqual(row["user_id"], target_spoofed_id)

    def test_06_soc_status_and_admin_unlock(self):
        """Verify Admin SOC endpoint displays posture and supports 1-click IP/account unlock."""
        with self.client.session_transaction() as sess:
            sess["user"] = {"id": 1, "username": "admin", "role": "admin"}
            sess["csrf_token"] = self.csrf_token

        # Trigger a test lockout
        test_ip = "192.168.99.1"
        rate_limiter.record_failure(test_ip, "test_user_locked")
        rate_limiter.record_failure(test_ip, "test_user_locked")
        rate_limiter.record_failure(test_ip, "test_user_locked")
        rate_limiter.record_failure(test_ip, "test_user_locked")
        rate_limiter.record_failure(test_ip, "test_user_locked")

        # Fetch SOC status
        res = self.client.get("/api/admin/security/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("security_posture", data)
        self.assertIn("active_lockouts", data)

        # Admin unlocks target
        res_unlock = self.client.post("/api/admin/security/unlock", json={
            "target": f"ip:{test_ip}"
        }, headers={"X-CSRFToken": self.csrf_token})
        self.assertEqual(res_unlock.status_code, 200)
        self.assertTrue(res_unlock.get_json()["success"])

        is_locked, _ = rate_limiter.is_locked(f"ip:{test_ip}")
        self.assertFalse(is_locked)


if __name__ == "__main__":
    unittest.main()
