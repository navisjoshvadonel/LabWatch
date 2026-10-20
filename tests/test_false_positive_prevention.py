"""
test_false_positive_prevention.py
Monitoring False-Positive Prevention & Laboratory Operating Hours Test Suite
Mepco Schlenk Engineering College (Autonomous), Sivakasi
Department of Artificial Intelligence and Data Science (AIDS)

Validates:
1. 3-Sweep Debounce Threshold: Transient ping drops (1 or 2 failures) do not flip status to Offline.
2. Hard Offline Confirmation: Exactly 3 consecutive failures confirm Offline state.
3. Operating Schedule Engine: Correctly evaluates operating days (Mon-Sat) and hours (08:00-17:30).
4. Off-Hours False-Alarm Suppression: Ticket creation is suppressed outside lab working hours.
5. Admin Schedule API (/api/admin/schedule): Validates GET and POST schedule matrix queries and updates.
6. Deployment Posture (/api/deployment/status): Confirms 90s sweep timeout and debounce posture.
7. Zero Emojis Compliance: Certified 100% clean institutional standard.
"""

from datetime import datetime
import json
import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from python_server import (
    app,
    get_db_connection,
    DAEMON_SECRET_TOKEN,
    is_lab_operational_hours,
    LAB_OPERATING_SCHEDULE
)


class TestFalsePositivePrevention(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.csrf_token = "mepco_test_csrf_token_2026"
        with self.client.session_transaction() as sess:
            sess["user"] = {
                "id": 1,
                "username": "admin",
                "full_name": "System Administrator",
                "role": "admin",
                "email": "admin@mepcoeng.ac.in"
            }
            sess["csrf_token"] = self.csrf_token

        # Ensure test PC PC-02 starts with all-online ping history and Online status
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE COMPUTERS SET status = 'Online', ping_history = '[1,1,1,1,1,1,1,1,1,1]' WHERE pc_number = 'PC-02'"
            )
            # Remove any active test tickets on PC-02
            cursor.execute("SELECT id FROM COMPUTERS WHERE pc_number = 'PC-02'")
            comp = cursor.fetchone()
            if comp:
                cursor.execute("DELETE FROM TICKETS WHERE computer_id = ?", (comp["id"],))
            conn.commit()
        finally:
            conn.close()

    def test_01_debounce_transient_single_failure_holds_status(self):
        """Verify that a single missed ping (Fail 1/3) does not flip workstation to Offline or create a ticket."""
        res = self.client.post("/api/pc-status", json={
            "pc_id": "PC-02",
            "status": "offline",
            "ip_address": "192.168.1.102"
        }, headers={"X-Daemon-Token": DAEMON_SECRET_TOKEN})
        self.assertEqual(res.status_code, 200)

        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT status, ping_history FROM COMPUTERS WHERE pc_number = 'PC-02'")
            row = cursor.fetchone()
            # Status should be retained as Online
            self.assertEqual(row["status"], "Online")
            hist = json.loads(row["ping_history"])
            self.assertEqual(hist[-1], 0)
            self.assertEqual(hist[-2:], [1, 0])

            # No ticket should be created
            cursor.execute(
                "SELECT COUNT(*) FROM TICKETS t JOIN COMPUTERS c ON t.computer_id = c.id WHERE c.pc_number = 'PC-02'"
            )
            self.assertEqual(cursor.fetchone()[0], 0)
        finally:
            conn.close()

    def test_02_debounce_two_failures_still_holds_status(self):
        """Verify that 2 missed pings (Fail 2/3) still do not flip status to Offline."""
        # 1st drop
        self.client.post("/api/pc-status", json={
            "pc_id": "PC-02",
            "status": "offline",
            "ip_address": "192.168.1.102"
        }, headers={"X-Daemon-Token": DAEMON_SECRET_TOKEN})

        # 2nd drop
        res = self.client.post("/api/pc-status", json={
            "pc_id": "PC-02",
            "status": "offline",
            "ip_address": "192.168.1.102"
        }, headers={"X-Daemon-Token": DAEMON_SECRET_TOKEN})
        self.assertEqual(res.status_code, 200)

        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT status, ping_history FROM COMPUTERS WHERE pc_number = 'PC-02'")
            row = cursor.fetchone()
            self.assertEqual(row["status"], "Online")
            hist = json.loads(row["ping_history"])
            self.assertEqual(hist[-2:], [0, 0])

            # Still no ticket
            cursor.execute(
                "SELECT COUNT(*) FROM TICKETS t JOIN COMPUTERS c ON t.computer_id = c.id WHERE c.pc_number = 'PC-02'"
            )
            self.assertEqual(cursor.fetchone()[0], 0)
        finally:
            conn.close()

    def test_03_debounce_three_failures_confirms_hard_offline(self):
        """Verify that 3 consecutive missed pings (3/3) confirm hard Offline and trigger ticket during operational hours."""
        # Force schedule check to return operational for this test
        old_val = os.environ.get("LABPULSE_ENFORCE_SCHEDULE")
        os.environ["LABPULSE_ENFORCE_SCHEDULE"] = "0"
        try:
            for _ in range(3):
                res = self.client.post("/api/pc-status", json={
                    "pc_id": "PC-02",
                    "status": "offline",
                    "ip_address": "192.168.1.102"
                }, headers={"X-Daemon-Token": DAEMON_SECRET_TOKEN})
                self.assertEqual(res.status_code, 200)

            conn = get_db_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT status, ping_history FROM COMPUTERS WHERE pc_number = 'PC-02'")
                row = cursor.fetchone()
                self.assertEqual(row["status"], "Offline")
                hist = json.loads(row["ping_history"])
                self.assertEqual(hist[-3:], [0, 0, 0])

                # Automated ticket should now be created
                cursor.execute(
                    "SELECT COUNT(*) FROM TICKETS t JOIN COMPUTERS c ON t.computer_id = c.id WHERE c.pc_number = 'PC-02' AND t.status = 'Pending'"
                )
                self.assertGreaterEqual(cursor.fetchone()[0], 1)
            finally:
                conn.close()
        finally:
            if old_val is None:
                os.environ.pop("LABPULSE_ENFORCE_SCHEDULE", None)
            else:
                os.environ["LABPULSE_ENFORCE_SCHEDULE"] = old_val

    def test_04_operating_schedule_evaluation(self):
        """Verify operating schedule correctly checks working hours and days."""
        # Mon at 10:30 AM -> True
        dt_in = datetime(2026, 10, 19, 10, 30) # Monday
        is_op, reason = is_lab_operational_hours(1, check_time=dt_in)
        self.assertTrue(is_op)
        self.assertIn("active laboratory operating hours", reason)

        # Mon at 18:30 (6:30 PM) -> False (outside working hours)
        dt_evening = datetime(2026, 10, 19, 18, 30)
        is_op, reason = is_lab_operational_hours(1, check_time=dt_evening)
        self.assertFalse(is_op)
        self.assertIn("Outside active laboratory hours", reason)

        # Sunday at 11:00 AM -> False (closed on Sunday)
        dt_sunday = datetime(2026, 10, 18, 11, 0) # Sunday
        is_op, reason = is_lab_operational_hours(1, check_time=dt_sunday)
        self.assertFalse(is_op)
        self.assertIn("Outside operating days", reason)

    def test_05_off_hours_suppresses_automated_ticket_creation(self):
        """Verify that outside lab operating hours, 3 offline sweeps do not create a ticket."""
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("UPDATE COMPUTERS SET ping_history = '[0,0,0,0,0,0,0,0,0,0]' WHERE pc_number = 'PC-02'")
            cursor.execute("SELECT id FROM COMPUTERS WHERE pc_number = 'PC-02'")
            comp_id = cursor.fetchone()["id"]
            cursor.execute("DELETE FROM TICKETS WHERE computer_id = ?", (comp_id,))
            conn.commit()
        finally:
            conn.close()

        # Temporarily restrict schedule start_time to future time to simulate off-hours
        orig_sched = dict(LAB_OPERATING_SCHEDULE.get(1, LAB_OPERATING_SCHEDULE["default"]))
        LAB_OPERATING_SCHEDULE[1] = {
            **orig_sched,
            "start_time": "23:58",
            "end_time": "23:59"
        }
        try:
            res = self.client.post("/api/pc-status", json={
                "pc_id": "PC-02",
                "status": "offline",
                "ip_address": "192.168.1.102"
            }, headers={"X-Daemon-Token": DAEMON_SECRET_TOKEN})
            self.assertEqual(res.status_code, 200)

            # Ticket creation should have been suppressed
            conn = get_db_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM TICKETS WHERE computer_id = ?", (comp_id,))
                self.assertEqual(cursor.fetchone()[0], 0)
            finally:
                conn.close()
        finally:
            LAB_OPERATING_SCHEDULE[1] = orig_sched

    def test_06_admin_schedule_api(self):
        """Verify GET and POST /api/admin/schedule for timetable queries and updates."""
        # GET schedule
        res = self.client.get("/api/admin/schedule")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("schedules", data)
        self.assertIn("default", data["schedules"])

        # POST update schedule
        post_res = self.client.post("/api/admin/schedule", json={
            "lab_id": 1,
            "start_time": "08:15",
            "end_time": "17:15",
            "operating_days": [0, 1, 2, 3, 4, 5],
            "schedule_slots": [
                {"period": "FN", "timing": "09:00-12:30", "subject": "Deep Learning Laboratory"}
            ]
        }, headers={"X-CSRFToken": self.csrf_token})
        self.assertEqual(post_res.status_code, 200)
        post_data = post_res.get_json()
        self.assertTrue(post_data["success"])
        self.assertEqual(post_data["schedule"]["start_time"], "08:15")
        self.assertEqual(len(post_data["schedule"]["schedule_slots"]), 1)

    def test_07_deployment_posture_includes_monitoring_tier(self):
        """Verify /api/deployment/status reports 90s sweep timeout and debounce posture."""
        res = self.client.get("/api/deployment/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("monitoring_tier", data)
        mt = data["monitoring_tier"]
        self.assertEqual(mt["sweep_timeout_sec"], 90)
        self.assertEqual(mt["debounce_threshold_sweeps"], 3)
        self.assertIn("current_operational_status", mt)

    def test_08_zero_emojis_compliance(self):
        """Ensure test file is 100% compliant with zero emojis policy."""
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
            content = f.read()
        for idx, line in enumerate(content.splitlines(), start=1):
            for ch in line:
                self.assertFalse(is_emoji(ch), f"Forbidden emoji on line {idx}: {ch}")


if __name__ == "__main__":
    unittest.main()
