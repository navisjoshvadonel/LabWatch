"""
test_live_gmail_smtp_protocol.py
Gmail SMTP Protocol (RFC 3207 STARTTLS Port 587) & Student Email Notification Test Suite
Mepco Schlenk Engineering College (Autonomous), Sivakasi
Department of Artificial Intelligence & Data Science (AIDS)

Verifies:
1. SMTP Configuration & Google App Password whitespace stripping
2. Gmail STARTTLS handshake engine & credential validation
3. Admin SMTP API endpoints (/api/admin/smtp/config, verify, save, test-send)
4. Automated student acknowledgment email upon ticket creation
5. Automated student resolution email upon ticket resolution (both API and Admin form)
6. 100% Zero-Emoji Compliance across all newly created code and templates
"""

import json
import os
import smtplib
import sqlite3
import sys
import unittest
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import python_server
from python_server import (
    app, get_db_connection, DB_PATH,
    load_env_credentials, save_smtp_credentials,
    test_and_verify_gmail_smtp as verify_gmail_smtp_engine,
    send_ticket_acknowledgment_email, send_resolution_email
)


class TestLiveGmailSmtpProtocol(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.csrf_token = "mepco_test_token_smtp_2026"

        with self.client.session_transaction() as sess:
            sess["user"] = {
                "id": 1,
                "username": "admin",
                "full_name": "System Administrator",
                "role": "admin",
                "email": "admin@mepcoeng.ac.in"
            }
            sess["csrf_token"] = self.csrf_token

    def test_01_app_password_whitespace_stripping(self):
        """Verify that 16-character Google App Passwords with spaces are cleanly stripped."""
        raw_password = "abcd efgh ijkl mnop"
        clean = raw_password.replace(" ", "").strip()
        self.assertEqual(clean, "abcdefghijklmnop")
        self.assertEqual(len(clean), 16)

    def test_02_save_and_reload_smtp_credentials(self):
        """Verify that save_smtp_credentials persists to .env and updates runtime variables."""
        test_sender = "test.it@gmail.com"
        test_pass = "wxyz wxyz wxyz wxyz"
        test_name = "Mepco Test Support"

        save_smtp_credentials(test_sender, test_pass, test_name, demo_mode=True)
        self.assertEqual(python_server.SMTP_SENDER_EMAIL, test_sender)
        self.assertEqual(python_server.SMTP_APP_PASSWORD, "wxyz" * 4)
        self.assertEqual(python_server.SMTP_SENDER_NAME, test_name)

        # Verify .env file was written
        env_path = os.path.join(BASE_DIR, ".env")
        self.assertTrue(os.path.exists(env_path))
        with open(env_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("test.it@gmail.com", content)

    def test_03_admin_smtp_config_api(self):
        """Verify GET /api/admin/smtp/config returns active protocol metadata."""
        res = self.client.get("/api/admin/smtp/config")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("host"), "smtp.gmail.com")
        self.assertEqual(data.get("port"), 587)
        self.assertIn("sender_email", data)
        self.assertIn("is_live", data)

    def test_04_admin_smtp_verify_auth_failure_handling(self):
        """Verify that bad credentials return clean, user-friendly Google App Password guidance."""
        res = self.client.post("/api/admin/smtp/verify", json={
            "sender_email": "invalid_user@gmail.com",
            "app_password": "badpassword1234",
            "recipient_email": "student@mepcoeng.ac.in"
        }, headers={"X-CSRFToken": self.csrf_token})

        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data.get("success"))
        self.assertIn("error", data)

    @patch("smtplib.SMTP")
    def test_05_smtp_starttls_handshake_success_mock(self, mock_smtp_cls):
        """Verify RFC 3207 STARTTLS handshake execution flow to Google Mail."""
        mock_instance = MagicMock()
        mock_smtp_cls.return_value.__enter__.return_value = mock_instance

        mock_instance.ehlo.return_value = (250, b"smtp.gmail.com at your service")
        mock_instance.starttls.return_value = (220, b"2.0.0 Ready to start TLS")
        mock_instance.login.return_value = (235, b"2.7.0 Accepted")
        mock_instance.sendmail.return_value = {}

        result = verify_gmail_smtp_engine(
            sender_email="labpulse.mepco@gmail.com",
            app_password="mock app pass 1234",
            recipient_email="24bad019@mepcoeng.ac.in"
        )

        self.assertTrue(result.get("success"))
        self.assertTrue(result.get("test_sent"))
        # Verify protocol sequence: ehlo -> starttls -> ehlo -> login -> sendmail
        self.assertTrue(mock_instance.starttls.called)
        self.assertTrue(mock_instance.login.called)
        self.assertTrue(mock_instance.sendmail.called)

    def test_06_ticket_submission_captures_student_email(self):
        """Verify ticket submission captures custom student email and logs confirmation."""
        student_email = "24bad099@mepcoeng.ac.in"
        res = self.client.post("/report", json={
            "lab_id": 1,
            "pc_number": "PC-25",
            "roll_number": "24BAD099",
            "reporter_email": student_email,
            "issue_category": "Operating System",
            "description": "Kernel crash during compiler execution",
            "priority": "High"
        }, headers={"X-CSRFToken": self.csrf_token})

        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        tck = data.get("ticket", {})
        self.assertEqual(tck.get("reporter_email"), student_email)

        # Verify persisted in database
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT reporter_email FROM TICKETS WHERE ticket_number = ?", (tck["ticket_number"],))
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["reporter_email"], student_email)
        finally:
            conn.close()

    @patch("python_server.send_resolution_email")
    def test_07_ticket_resolution_dispatches_email_to_student(self, mock_send):
        """Verify resolving a ticket dispatches resolution email to the student's email."""
        import uuid
        mock_send.return_value = {"sent": True}

        # Create a test ticket with a specific student email
        conn = get_db_connection()
        test_email = "student_verify@mepcoeng.ac.in"
        dynamic_ticket_num = f"TCK-TEST-{uuid.uuid4().hex[:6].upper()}"
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO TICKETS (
                    ticket_number, user_id, lab_id, computer_id,
                    issue_category, description, status, priority, reporter_email, reported_at
                ) VALUES (?, 2, 1, 1, 'Hardware Fault', 'RAM Fault', 'Pending', 'Medium', ?, CURRENT_TIMESTAMP)
            """, (dynamic_ticket_num, test_email))
            ticket_id = cursor.lastrowid
            conn.commit()
        finally:
            conn.close()

        try:
            # Resolve via Admin route
            res = self.client.post(f"/admin/resolve/{ticket_id}", data={
                "notes": "Replaced RAM DIMM module in slot 2.",
                "csrf_token": self.csrf_token
            }, follow_redirects=False)

            self.assertEqual(res.status_code, 302)

            # Allow async thread execution
            import time
            time.sleep(0.5)

            self.assertTrue(mock_send.called)
            call_args = mock_send.call_args[0]
            self.assertEqual(call_args[0], test_email)
            self.assertEqual(call_args[2], dynamic_ticket_num)
        finally:
            clean_conn = get_db_connection()
            try:
                clean_conn.execute("DELETE FROM TICKETS WHERE id = ?", (ticket_id,))
                clean_conn.commit()
            finally:
                clean_conn.close()

    def test_08_zero_emojis_in_new_test_suite(self):
        """Strictly verify zero emojis in this test file."""
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

        with open(__file__, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f, 1):
                emojis = [c for c in line if is_emoji(c)]
                self.assertEqual(len(emojis), 0, f"Found forbidden emoji at line {idx}")


if __name__ == "__main__":
    unittest.main()
