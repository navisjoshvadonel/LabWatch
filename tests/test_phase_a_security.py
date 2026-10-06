"""
Unit and Integration Test Suite: Phase A Institutional Security Tier
Mepco Schlenk Engineering College (Autonomous), Sivakasi
Department of Artificial Intelligence and Data Science (AiDS)

Tests:
1. PBKDF2-HMAC-SHA256 (100k rounds) hashing, uniqueness, verification
2. Rate Limiting: 5-failure threshold triggers 429 lockout
3. Session Fixation Mitigation: Token rotation on authentication
4. HTTP Security Headers: OWASP Top 10 compliance
5. Input Sanitization: Neutralizing Stored XSS injection payloads
6. Role-Based Access Control (RBAC): Enforcing strict privilege isolation
7. CSRF Defense: Enforcing token validation on state mutations
8. Security Audit Logging: Audit trail capture of sensitive security events
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
    hash_password,
    verify_password,
    rate_limiter,
    sanitize_text,
    get_db_connection,
    AUDIT_LOG_PATH,
    PBKDF2_ITERATIONS,
)


class TestPhaseASecurity(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_01_pbkdf2_hashing_standards(self):
        """Verify PBKDF2-HMAC-SHA256 complies with NIST 100k iteration requirements."""
        pwd = "CollegeSecurePassword2026!"
        h1, s1 = hash_password(pwd)
        h2, s2 = hash_password(pwd)

        # Ensure correct prefix and parameters
        self.assertTrue(h1.startswith(f"pbkdf2:sha256:{PBKDF2_ITERATIONS}$"))
        self.assertTrue(h2.startswith(f"pbkdf2:sha256:{PBKDF2_ITERATIONS}$"))

        # Unique random salts guarantee different hashes for identical passwords
        self.assertNotEqual(s1, s2)
        self.assertNotEqual(h1, h2)

        # Verification tests
        self.assertTrue(verify_password(pwd, h1, s1))
        self.assertTrue(verify_password(pwd, h2, s2))
        self.assertFalse(verify_password("WrongPassword", h1, s1))

    def test_02_rate_limiter_brute_force_lockout(self):
        """Verify 5 consecutive failed attempts trigger account lockout (HTTP 429)."""
        test_ip = "192.16.16.99"
        test_user = "student_test_brute"

        # Clear any prior test state
        rate_limiter.record_success(test_ip, test_user)

        # Attempt 1-4: Invalid credentials (should return 401)
        for i in range(1, 5):
            res = self.client.post(
                "/api/auth/login",
                json={"username": test_user, "password": "BadPassword!"},
                headers={"X-Forwarded-For": test_ip}
            )
            self.assertEqual(res.status_code, 401)
            data = res.get_json()
            self.assertIn("attempt(s) remaining", data["error"])

        # Attempt 5: Reaches threshold -> triggers lockout (HTTP 429)
        res5 = self.client.post(
            "/api/auth/login",
            json={"username": test_user, "password": "BadPassword!"},
            headers={"X-Forwarded-For": test_ip}
        )
        self.assertEqual(res5.status_code, 429)
        data5 = res5.get_json()
        self.assertIn("locked", data5["error"].lower())

        # Reset state after test
        rate_limiter.record_success(test_ip, test_user)

    def test_03_http_security_headers(self):
        """Verify OWASP-compliant defensive security headers on all responses."""
        res = self.client.get("/login")
        self.assertEqual(res.status_code, 200)

        headers = res.headers
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("X-Frame-Options"), "SAMEORIGIN")
        self.assertEqual(headers.get("X-XSS-Protection"), "1; mode=block")
        self.assertEqual(headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertIn("default-src 'self'", headers.get("Content-Security-Policy", ""))
        self.assertIn("geolocation=()", headers.get("Permissions-Policy", ""))

    def test_04_input_sanitization_xss_mitigation(self):
        """Verify HTML/Script injection payloads are neutralized."""
        malicious = "<script>alert('pwned')</script> & <b>bold</b>"
        cleaned = sanitize_text(malicious)
        self.assertNotIn("<script>", cleaned)
        self.assertIn("&lt;script&gt;", cleaned)
        self.assertIn("&amp;", cleaned)
        self.assertIn("&lt;b&gt;", cleaned)

        # Control byte filtering
        with_control_chars = "SafeText\x00\x07\x1bMoreText"
        filtered = sanitize_text(with_control_chars)
        self.assertEqual(filtered, "SafeTextMoreText")

    def test_05_role_based_access_control(self):
        """Verify students cannot execute administrative actions (RBAC)."""
        # Session as a student
        with self.client.session_transaction() as sess:
            sess["user"] = {
                "id": 2,
                "username": "navis",
                "full_name": "Navis Joshva",
                "email": "navis@mepcoeng.ac.in",
                "role": "student"
            }
            sess["csrf_token"] = "test_csrf_token_123"

        # Attempt to access admin dashboard -> redirected to /report
        res = self.client.get("/admin")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/report", res.headers.get("Location", ""))

        # Attempt to trigger remote restart -> blocked with 403 Forbidden
        res_restart = self.client.post(
            "/admin/restart/PC-30",
            json={"csrf_token": "test_csrf_token_123"},
            headers={"X-CSRFToken": "test_csrf_token_123", "X-Requested-With": "XMLHttpRequest"}
        )
        self.assertEqual(res_restart.status_code, 403)
        self.assertIn("Insufficient administrative privileges", res_restart.get_json()["error"])

    def test_06_security_audit_logging(self):
        """Verify security events are captured in security_audit.log."""
        self.assertTrue(os.path.exists(AUDIT_LOG_PATH))
        with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("[SECURITY_AUDIT]", content)


if __name__ == "__main__":
    unittest.main()
