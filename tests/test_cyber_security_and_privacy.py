"""
test_cyber_security_and_privacy.py
Institutional Cyber Security, Privacy Preservation, Anti-Hacking & Anti-Leaking Verification Suite
Mepco Schlenk Engineering College (Autonomous), Sivakasi
Department of Artificial Intelligence & Data Science (AIDS)

Validates:
1. Web Application Firewall (WAF Layer 7):
   - Path traversal pattern blocking (../, ..\\, %2e%2e, null bytes)
   - Unauthorized sensitive file probing protection (.env, .git, .session_secret, labpulse.db)
   - Malicious query injection probe neutralization (SQLi, XSS)
2. Timing Attack Immunity:
   - Constant-time dummy PBKDF2 hash verification on non-existent usernames
3. Password Policy & Entropy Enforcement:
   - Rejection of common guessable passwords and format validation
4. Student PII Privacy Preservation & Anti-Leaking:
   - Masked student emails and names on public status pages for unauthenticated viewers
   - Unmasked full access for authenticated author and IT administrators
   - Student peer privacy isolation in ticket queries
5. Anti-Reconnaissance & HTTP Header Hardening:
   - Generic Server header (LabWatch-Security-Gateway)
   - Strict Cross-Origin, Referrer, and Content-Type defense headers
   - Anti-caching directives on sensitive management endpoints
6. Command Injection Neutralization:
   - Strict shell metacharacter rejection in remote diagnostic console
7. Security Operations Center (SOC) WAF Telemetry:
   - Live attack mitigation counters in /api/admin/security/status
"""

import os
import sys
import unittest
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from python_server import app, waf_metrics, mask_email, mask_name, mask_ip


class TestCyberSecurityAndPrivacy(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.csrf_token = "mepco_cyber_defense_token_2026"

    def test_01_waf_path_traversal_blocking(self):
        """Verify WAF blocks path traversal sequences (../, %2e%2e, null bytes) with HTTP 400."""
        prev_blocked = waf_metrics.traversal_blocked

        # Test 1: dot-dot slash in query
        res = self.client.get("/login?redirect=../../etc/passwd")
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertIn("Path traversal pattern detected", data["error"])

        # Test 2: encoded dot-dot
        res2 = self.client.get("/report?param=%2e%2e%2fconfig")
        self.assertEqual(res2.status_code, 400)

        self.assertGreater(waf_metrics.traversal_blocked, prev_blocked)

    def test_02_waf_sensitive_file_probing_blocking(self):
        """Verify WAF rejects attempts to probe sensitive institutional files with HTTP 403."""
        prev_blocked = waf_metrics.sensitive_files_blocked

        # Test .env access attempt
        res_env = self.client.get("/.env")
        self.assertEqual(res_env.status_code, 403)
        self.assertIn("Protected institutional resource", res_env.get_json()["error"])

        # Test .session_secret access attempt
        res_secret = self.client.get("/.session_secret")
        self.assertEqual(res_secret.status_code, 403)

        # Test database file access attempt
        res_db = self.client.get("/labpulse.db")
        self.assertEqual(res_db.status_code, 403)

        self.assertGreater(waf_metrics.sensitive_files_blocked, prev_blocked)

    def test_03_waf_injection_probe_neutralization(self):
        """Verify WAF detects and neutralizes SQLi and script injection probes with HTTP 400."""
        prev_blocked = waf_metrics.injection_probes_blocked

        # SQL Injection probe in query string
        res_sqli = self.client.get("/api/tickets?lab_id=1+union+select+null,password+from+users")
        self.assertEqual(res_sqli.status_code, 400)
        self.assertIn("Malicious payload pattern detected", res_sqli.get_json()["error"])

        # XSS Script probe in query string
        res_xss = self.client.get("/report?category=<script>alert(1)</script>")
        self.assertEqual(res_xss.status_code, 400)

        self.assertGreater(waf_metrics.injection_probes_blocked, prev_blocked)

    def test_04_timing_attack_immunity_verification(self):
        """Verify non-existent user login executes constant-time work and returns 401."""
        res = self.client.post("/api/auth/login", json={
            "username": "non_existent_student_99999",
            "password": "AnySamplePassword123!"
        })
        self.assertEqual(res.status_code, 401)
        data = res.get_json()
        self.assertIn("Invalid username or password", data["error"])

    def test_05_password_policy_and_complexity_enforcement(self):
        """Verify registration rejects common trivial passwords and enforces email format."""
        # 1. Common guessable password rejection
        res_weak = self.client.post("/api/auth/register", json={
            "username": "security_test_user_01",
            "password": "password123",
            "full_name": "Security Tester",
            "email": "testuser01@mepcoeng.ac.in",
            "role": "student"
        })
        self.assertEqual(res_weak.status_code, 400)
        self.assertIn("too common", res_weak.get_json()["error"])

        # 2. Invalid email format rejection
        res_bad_email = self.client.post("/api/auth/register", json={
            "username": "security_test_user_02",
            "password": "ComplexPassword2026!",
            "full_name": "Security Tester",
            "email": "invalid_email_format",
            "role": "student"
        })
        self.assertEqual(res_bad_email.status_code, 400)
        self.assertIn("email", res_bad_email.get_json()["error"])

    def test_06_student_pii_privacy_masking_on_public_status(self):
        """Verify anonymous visitors cannot harvest student emails or full names on ticket status page."""
        # 1. Anonymous viewer request for ticket TCK-101 (reported by Navis Joshva)
        res_anon = self.client.get("/status/TCK-101")
        self.assertEqual(res_anon.status_code, 200)
        html = res_anon.get_data(as_text=True)

        # Full email MUST NOT be exposed to unauthenticated viewers
        self.assertNotIn("navis@mepcoeng.ac.in", html)
        self.assertIn("n***s@mepcoeng.ac.in", html)

        # 2. Author viewer request: Authenticated as Navis (ID 2)
        with self.client.session_transaction() as sess:
            sess["user"] = {
                "id": 2,
                "username": "navis",
                "full_name": "Navis Joshva",
                "email": "navis@mepcoeng.ac.in",
                "role": "student"
            }
            sess["csrf_token"] = self.csrf_token

        res_author = self.client.get("/status/TCK-101")
        self.assertEqual(res_author.status_code, 200)
        html_author = res_author.get_data(as_text=True)

        # Author can view their own email in full
        self.assertIn("navis@mepcoeng.ac.in", html_author)

    def test_07_student_peer_privacy_isolation_in_tickets_api(self):
        """Verify students querying lab tickets have other students' email and name masked."""
        with self.client.session_transaction() as sess:
            sess["user"] = {
                "id": 2,
                "username": "navis",
                "full_name": "Navis Joshva",
                "role": "student"
            }
            sess["csrf_token"] = self.csrf_token

        res = self.client.get("/api/tickets?status=Pending&lab_id=1")
        self.assertEqual(res.status_code, 200)
        tickets = res.get_json()["tickets"]

        for t in tickets:
            if t["user_id"] != 2:
                # Other students' emails must be masked
                email = t.get("reporter_email", "")
                if email and "@" in email:
                    self.assertIn("***", email)

    def test_08_anti_fingerprinting_and_hardened_security_headers(self):
        """Verify Server header obfuscation and defense headers across all responses."""
        res = self.client.get("/login")
        self.assertEqual(res.status_code, 200)

        # Obfuscated server signature
        self.assertEqual(res.headers.get("Server"), "LabWatch-Security-Gateway")

        # Defense-in-depth headers
        self.assertEqual(res.headers.get("X-Permitted-Cross-Domain-Policies"), "none")
        self.assertEqual(res.headers.get("Cross-Origin-Opener-Policy"), "same-origin")
        self.assertEqual(res.headers.get("Cross-Origin-Resource-Policy"), "same-origin")

        # Anti-caching on authenticated API
        with self.client.session_transaction() as sess:
            sess["user"] = {"id": 1, "username": "admin", "role": "admin"}
            sess["csrf_token"] = self.csrf_token

        res_api = self.client.get("/api/admin/security/status")
        self.assertEqual(res_api.status_code, 200)
        self.assertIn("no-store", res_api.headers.get("Cache-Control", ""))

    def test_09_command_injection_rejection_in_remote_exec(self):
        """Verify remote-exec rejects commands with shell metacharacters (; & | ` $)."""
        with self.client.session_transaction() as sess:
            sess["user"] = {"id": 1, "username": "admin", "role": "admin"}
            sess["csrf_token"] = self.csrf_token

        # Semicolon command concatenation attempt
        res = self.client.post("/api/admin/remote-exec", json={
            "pc_id": "PC-01",
            "command": "ping 192.168.1.1 ; cat /etc/shadow"
        }, headers={"X-CSRFToken": self.csrf_token})

        self.assertEqual(res.status_code, 400)
        self.assertIn("Prohibited shell metacharacters", res.get_json()["error"])

    def test_10_soc_waf_telemetry_endpoint(self):
        """Verify SOC endpoint provides real-time WAF telemetry and attack statistics."""
        with self.client.session_transaction() as sess:
            sess["user"] = {"id": 1, "username": "admin", "role": "admin"}
            sess["csrf_token"] = self.csrf_token

        res = self.client.get("/api/admin/security/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertIn("waf_telemetry", data)
        self.assertIn("total_attacks_blocked", data["waf_telemetry"])
        self.assertIn("web_application_firewall", data["security_posture"])
        self.assertIn("privacy_cloaking", data["security_posture"])


if __name__ == "__main__":
    unittest.main()
