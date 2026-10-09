"""
test_edge_case_failures.py
Tests targeting edge cases and high-concurrency race conditions:
1. Concurrent ticket creation race conditions (Collision prevention).
2. Non-numeric query parameters on GET /api/tickets (?user_id=invalid).
3. Malformed/Empty X-Forwarded-For headers.
4. Explicitly None session user object handling.
5. Non-existent workstation diagnostic probe (/api/diagnose/PC-999).
"""

import concurrent.futures
import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from python_server import app


class TestEdgeCaseFailures(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.csrf_token = "mepco_edge_case_token_2026"
        with self.client.session_transaction() as sess:
            sess["user"] = {
                "id": 1,
                "username": "admin",
                "full_name": "System Administrator",
                "role": "admin"
            }
            sess["csrf_token"] = self.csrf_token

    def test_01_malformed_user_id_query_filter(self):
        """Pass non-numeric user_id to /api/tickets (Must return 200 or 400, NEVER 500)."""
        res = self.client.get("/api/tickets?user_id=invalid_text_param")
        self.assertNotEqual(res.status_code, 500, "Server crashed with 500 on non-numeric user_id")
        self.assertIn(res.status_code, (200, 400))

    def test_02_malformed_lab_id_query_filter(self):
        """Pass special characters to /api/tickets?lab_id="""
        res = self.client.get("/api/tickets?lab_id=invalid';--")
        self.assertNotEqual(res.status_code, 500, "Server crashed with 500 on malformed lab_id")
        self.assertIn(res.status_code, (200, 400))

    def test_03_malformed_empty_x_forwarded_for_header(self):
        """Pass malformed empty commas in X-Forwarded-For header (Must not crash)."""
        res = self.client.get(
            "/api/client/auto-detect",
            headers={"X-Forwarded-For": " , , "}
        )
        self.assertNotEqual(res.status_code, 500, "Server crashed on empty X-Forwarded-For header")
        self.assertEqual(res.status_code, 200)

    def test_04_session_user_explicitly_none(self):
        """Verify endpoints gracefully handle session['user'] = None without AttributeError."""
        with self.client.session_transaction() as sess:
            sess["user"] = None
            sess["csrf_token"] = self.csrf_token

        res = self.client.get("/api/tickets")
        # Should redirect to login or return 401, never 500 AttributeError
        self.assertIn(res.status_code, (302, 401))

    def test_05_diagnose_non_existent_workstation(self):
        """Probe non-existent PC (/api/diagnose/PC-999) - Must return 404, never 500."""
        res = self.client.get("/api/diagnose/PC-999-DOES-NOT-EXIST")
        self.assertEqual(res.status_code, 404)
        data = res.get_json()
        self.assertIn("error", data)

    def test_06_concurrent_ticket_creation_no_collision(self):
        """Fire 10 concurrent ticket creations to verify zero collisions in ticket_number generation."""
        def submit_ticket(idx):
            with self.app.test_client() as c:
                with c.session_transaction() as sess:
                    sess["user"] = {"id": 1, "username": "admin", "role": "admin"}
                    sess["csrf_token"] = f"csrf_{idx}"
                return c.post("/api/tickets", json={
                    "pc_number": "PC-18",
                    "issue_category": "Software Crash",
                    "description": f"Concurrent stress test ticket #{idx} verification",
                    "priority": "Medium"
                }, headers={"X-CSRFToken": f"csrf_{idx}"})

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(submit_ticket, i) for i in range(10)]
            responses = [f.result() for f in concurrent.futures.as_completed(futures)]

        for r in responses:
            self.assertEqual(r.status_code, 201, f"Concurrent ticket creation failed: {r.get_json()}")

        ticket_numbers = [r.get_json()["ticket"]["ticket_number"] for r in responses]
        self.assertEqual(len(ticket_numbers), len(set(ticket_numbers)), "Duplicate ticket numbers generated!")

    def test_07_put_ticket_string_and_invalid_technician_id(self):
        """PUT /api/tickets/<id> with string technician_id ('1') or invalid text must not crash with TypeError (500)."""
        res_list = self.client.get("/api/tickets")
        self.assertEqual(res_list.status_code, 200)
        tickets = res_list.get_json()["tickets"]
        self.assertTrue(len(tickets) > 0, "No tickets found to test PUT")
        target_id = tickets[0]["id"]

        # Test 1: string numeric ID
        res_str = self.client.put(f"/api/tickets/{target_id}", json={"technician_id": "1"}, headers={"X-CSRFToken": self.csrf_token})
        self.assertNotEqual(res_str.status_code, 500, "Server crashed with 500 on string numeric technician_id")
        self.assertEqual(res_str.status_code, 200)

        # Test 2: non-numeric string
        res_inv = self.client.put(f"/api/tickets/{target_id}", json={"technician_id": "invalid_tech"}, headers={"X-CSRFToken": self.csrf_token})
        self.assertNotEqual(res_inv.status_code, 500, "Server crashed with 500 on invalid technician_id")
        self.assertEqual(res_inv.status_code, 400)

    def test_08_daily_report_malformed_lab_id(self):
        """GET /api/reports/daily?lab_id=invalid must return 400 or 200, never 500."""
        res = self.client.get("/api/reports/daily?lab_id=invalid_text_lab")
        self.assertNotEqual(res.status_code, 500, "Server crashed with 500 on malformed lab_id in daily report")
        self.assertIn(res.status_code, (200, 400))

    def test_09_computers_malformed_lab_id(self):
        """GET /api/computers?lab_id=invalid must safely query or return 200, never 500."""
        res = self.client.get("/api/computers?lab_id=invalid_text_lab")
        self.assertNotEqual(res.status_code, 500, "Server crashed with 500 on malformed lab_id in computers API")
        self.assertEqual(res.status_code, 200)

    def test_10_technician_log_invalid_duration(self):
        """POST /api/technician/log with non-numeric duration_min must not crash with ValueError/TypeError."""
        res = self.client.post("/api/technician/log", json={
            "details": "Routine lab diagnostic sweep",
            "duration_min": "twenty_five_minutes"
        }, headers={"X-CSRFToken": self.csrf_token})
        self.assertNotEqual(res.status_code, 500, "Server crashed on invalid duration_min in technician log")
        self.assertIn(res.status_code, (201, 400))

    def test_11_remote_exec_non_string_command(self):
        """POST /api/admin/remote-exec with non-string command must not crash with AttributeError."""
        res = self.client.post("/api/admin/remote-exec", json={
            "pc_id": "PC-01",
            "command": 12345
        }, headers={"X-CSRFToken": self.csrf_token})
        self.assertNotEqual(res.status_code, 500, "Server crashed on non-string command in remote-exec")
        self.assertIn(res.status_code, (200, 400))

    def test_12_update_computer_duplicate_ip_conflict(self):
        """PUT /api/computers/1 with duplicate IP must return 409 Conflict, never unhandled 500."""
        # Find IP of PC #2
        res_comp2 = self.client.get("/api/computers?pc_id=PC-02")
        self.assertEqual(res_comp2.status_code, 200)
        pc2_ip = res_comp2.get_json()["computer"]["ip_address"]

        # Attempt to set PC #1's IP to PC #2's IP
        res_dup = self.client.put("/api/computers/1", json={"ip_address": pc2_ip}, headers={"X-CSRFToken": self.csrf_token})
        self.assertNotEqual(res_dup.status_code, 500, "Server crashed with 500 instead of returning 409 Conflict")
        self.assertEqual(res_dup.status_code, 409)

    def test_13_create_ticket_malformed_lab_id(self):
        """POST /api/tickets with non-numeric lab_id must return 400, never 500."""
        res = self.client.post("/api/tickets", json={
            "pc_number": "PC-01",
            "lab_id": "malformed_string_lab",
            "issue_category": "Software Crash",
            "description": "Validation test ticket with bad lab_id"
        }, headers={"X-CSRFToken": self.csrf_token})
        self.assertNotEqual(res.status_code, 500, "Server crashed on malformed lab_id in create_ticket")
        self.assertEqual(res.status_code, 400)

    def test_14_status_view_accessible_without_prior_session(self):
        """GET /status/TCK-101 anonymously (no student session) must render 200, never redirect to login."""
        with self.app.test_client() as anon_client:
            res = anon_client.get("/status/TCK-101")
            self.assertEqual(res.status_code, 200)
            self.assertIn(b"TCK-101", res.data)


if __name__ == "__main__":
    unittest.main()
