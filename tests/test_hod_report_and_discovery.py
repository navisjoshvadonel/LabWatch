"""
test_hod_report_and_discovery.py
Comprehensive Pytest / Unittest Suite for:
1. Department Matrix Sizing (60/30 PCs) and Designated Admin Workstations (DL-ADMIN-01 to LP-ADMIN-01)
2. Zero-Hardcoding Adaptive Inventory CRUD & C Daemon Synchronization
3. Adaptive LAN/Subnet ARP Discovery Engine
4. Cross-Lab Universal Remote Admin Terminal (ping, nvidia-smi, systeminfo, netstat, service)
5. HOD Executive Daily Operational Dossier & Official CSV Export
6. Manual Technician Duty Logging

Mepco Schlenk Engineering College (Autonomous), Sivakasi
Department of Artificial Intelligence & Data Science (AIDS)
"""

import os
import sys
import unittest
import json
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from python_server import app, get_db_connection


class TestHodReportAndDiscovery(unittest.TestCase):
    def _cleanup_test_artifacts(self):
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM COMPUTERS WHERE pc_number LIKE 'TEST-PC-%' OR ip_address = '10.173.240.115' OR id > 1086")
            conn.commit()
        finally:
            conn.close()

    def setUp(self):
        self._cleanup_test_artifacts()
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.csrf_token = "test_csrf_token_hod_dossier_2026"
        with self.client.session_transaction() as sess:
            sess["user"] = {
                "id": 1,
                "username": "admin",
                "full_name": "System Administrator",
                "role": "admin",
                "email": "admin@mepcoeng.ac.in"
            }
            sess["csrf_token"] = self.csrf_token

    def tearDown(self):
        self._cleanup_test_artifacts()

    def test_01_lab_capacities_and_admin_workstations(self):
        """Verify 246 total workstations across 6 labs, with exactly 6 designated Admin Workstations."""
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as cnt FROM COMPUTERS")
            total_pcs = cursor.fetchone()["cnt"]
            self.assertEqual(total_pcs, 246, f"Expected exactly 246 workstations in database, got {total_pcs}")

            # Verify admin workstations
            cursor.execute("SELECT pc_number, lab_id, is_admin FROM COMPUTERS WHERE is_admin = 1 ORDER BY lab_id")
            admin_pcs = [dict(r) for r in cursor.fetchall()]
            self.assertEqual(len(admin_pcs), 6, f"Expected 6 designated Admin Workstations, got {len(admin_pcs)}")

            admin_pc_names = [p["pc_number"] for p in admin_pcs]
            expected_admins = ["DL-ADMIN-01", "ML-ADMIN-01", "DS-ADMIN-01", "GA-ADMIN-01", "DA-ADMIN-01", "LP-ADMIN-01"]
            for ea in expected_admins:
                self.assertIn(ea, admin_pc_names, f"Expected Admin Workstation {ea} in database")

            # Verify capacities: DL and ML have 61 PCs (60 student + 1 admin), other 4 labs have 31 PCs (30 student + 1 admin)
            cursor.execute("SELECT lab_id, COUNT(*) as pc_count FROM COMPUTERS GROUP BY lab_id ORDER BY lab_id")
            lab_counts = {r["lab_id"]: r["pc_count"] for r in cursor.fetchall()}
            self.assertEqual(lab_counts[1], 61, "Deep Learning Lab should have 61 workstations")
            self.assertEqual(lab_counts[2], 61, "Machine Learning Lab should have 61 workstations")
            self.assertEqual(lab_counts[3], 31, "Data Science Lab should have 31 workstations")
            self.assertEqual(lab_counts[4], 31, "Generative AI Lab should have 31 workstations")
            self.assertEqual(lab_counts[5], 31, "Data Analytics Lab should have 31 workstations")
            self.assertEqual(lab_counts[6], 31, "Language Processing Lab should have 31 workstations")
        finally:
            conn.close()

    def test_02_dynamic_workstation_crud_and_daemon_sync(self):
        """Verify adaptive zero-hardcoded computer creation, updating, and deletion with C daemon sync."""
        new_pc_data = {
            "pc_number": "TEST-PC-99",
            "lab_id": 1,
            "ip_address": "192.168.1.99",
            "mac_address": "aa:bb:cc:dd:ee:99",
            "specs": "Test Node / 32GB RAM / RTX 4080",
            "is_admin": 0,
            "status": "Online"
        }

        # 1. POST Create
        res = self.client.post("/api/computers", json=new_pc_data, headers={"X-CSRFToken": self.csrf_token})
        self.assertEqual(res.status_code, 201)
        created_data = res.get_json()
        new_id = created_data["computer_id"]

        # Check export files were updated
        txt_path = os.path.join(BASE_DIR, "computers_monitor.txt")
        csv_path = os.path.join(BASE_DIR, "computers_monitor.csv")
        self.assertTrue(os.path.exists(txt_path))
        with open(txt_path, "r", encoding="utf-8") as f:
            txt_content = f.read()
        self.assertIn("TEST-PC-99", txt_content)
        self.assertIn("192.168.1.99", txt_content)

        # 2. PUT Update
        update_res = self.client.put(f"/api/computers/{new_id}", json={
            "status": "Offline",
            "specs": "Updated Specs 64GB DDR5"
        }, headers={"X-CSRFToken": self.csrf_token})
        self.assertEqual(update_res.status_code, 200)

        # 3. DELETE Clean-up
        del_res = self.client.delete(f"/api/computers/{new_id}", headers={"X-CSRFToken": self.csrf_token})
        self.assertEqual(del_res.status_code, 200)

        # Verify removal from computers_monitor.txt
        with open(txt_path, "r", encoding="utf-8") as f:
            txt_content_after = f.read()
        self.assertNotIn("TEST-PC-99", txt_content_after)

    def test_03_lan_adaptive_discovery(self):
        """Verify LAN / ARP discovery endpoint runs dynamically and returns structured discovery metrics."""
        res = self.client.post("/api/computers/discover", json={
            "lab_id": 1,
            "subnet": "192.168.1.0/24"
        }, headers={"X-CSRFToken": self.csrf_token})

        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("total_discovered", data)
        self.assertIn("registered_count", data)
        self.assertIn("updated_count", data)
        self.assertIn("results", data)

    def test_04_universal_remote_admin_command_execution(self):
        """Verify cross-lab admin console executes ping and nvidia-smi diagnostics and records technician log."""
        # 1. Test Ping
        res_ping = self.client.post("/api/admin/remote-exec", json={
            "pc_number": "DL-ADMIN-01",
            "command": "ping"
        }, headers={"X-CSRFToken": self.csrf_token})
        self.assertEqual(res_ping.status_code, 200)
        data_ping = res_ping.get_json()
        self.assertTrue(data_ping["success"])
        self.assertEqual(data_ping["pc_number"], "DL-ADMIN-01")
        self.assertIn("TTL", data_ping["output"])
        self.assertGreater(data_ping["duration_ms"], 0)

        # 2. Test NVIDIA-SMI
        res_gpu = self.client.post("/api/admin/remote-exec", json={
            "pc_number": "DL-ADMIN-01",
            "command": "nvidia-smi"
        }, headers={"X-CSRFToken": self.csrf_token})
        self.assertEqual(res_gpu.status_code, 200)
        data_gpu = res_gpu.get_json()
        self.assertIn("NVIDIA-SMI", data_gpu["output"])
        self.assertIn("RTX 4090", data_gpu["output"])

        # 3. Verify action was logged into TECHNICIAN_LOGS
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM TECHNICIAN_LOGS WHERE action_type = 'REMOTE_CONSOLE' ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertIn("DL-ADMIN-01", row["details"])
        finally:
            conn.close()

    def test_05_remote_admin_systeminfo_and_netstat(self):
        """Verify remote admin console executes systeminfo, netstat, service, and traceroute."""
        for cmd in ["systeminfo", "netstat", "service", "traceroute"]:
            res = self.client.post("/api/admin/remote-exec", json={
                "pc_number": "ML-ADMIN-01",
                "command": cmd
            }, headers={"X-CSRFToken": self.csrf_token})
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertTrue(data["success"])
            self.assertGreater(len(data["output"]), 20)

    def test_06_hod_daily_report_generation(self):
        """Verify HOD Daily Operational Dossier endpoint aggregates KPIs, scorecards, and lab availability."""
        today = datetime.now().strftime("%Y-%m-%d")
        res = self.client.get(f"/api/reports/daily?date={today}&lab_id=all")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        # Department & Institution Metadata
        self.assertIn("Mepco Schlenk Engineering College", data["institution"])
        self.assertIn("Artificial Intelligence & Data Science", data["department"])
        self.assertEqual(data["date"], today)

        # Executive Metrics
        metrics = data["metrics"]
        self.assertIn("total_actions", metrics)
        self.assertIn("tickets_resolved", metrics)
        self.assertIn("playbooks_executed", metrics)
        self.assertIn("department_uptime_pct", metrics)
        self.assertGreaterEqual(metrics["department_uptime_pct"], 0.0)

        # Technicians Scorecard
        techs = data["technicians"]
        self.assertIsInstance(techs, list)
        self.assertGreater(len(techs), 0)
        for t in techs:
            self.assertIn("technician_name", t)
            self.assertIn("efficiency_rating", t)
            self.assertIn("hours_logged", t)

        # Labs Matrix Breakdown
        labs = data["labs"]
        self.assertEqual(len(labs), 6, "Report should include all 6 departmental laboratories")
        for l in labs:
            self.assertIn("admin_workstation", l)
            self.assertIn("uptime_pct", l)
            self.assertIn("total_pcs", l)

        # Activity Ledger
        ledger = data["activity_ledger"]
        self.assertIsInstance(ledger, list)

    def test_07_hod_daily_report_csv_export(self):
        """Verify HOD Daily Report exports official CSV document with proper MIME headers and column headers."""
        today = datetime.now().strftime("%Y-%m-%d")
        res = self.client.get(f"/api/reports/daily/export?date={today}")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, "text/csv")
        self.assertIn(f"attachment; filename=LabPulse_Daily_Report_AIDS_{today}.csv", res.headers.get("Content-Disposition", ""))

        csv_text = res.get_data(as_text=True)
        first_line = csv_text.splitlines()[0]
        self.assertIn("Log_ID,Timestamp,Technician,Laboratory,Workstation,IP_Address,Action_Type,Details,Status,Duration_Min", first_line)

    def test_08_manual_technician_activity_logging(self):
        """Verify manual technician maintenance notes can be recorded directly into TECHNICIAN_LOGS."""
        log_payload = {
            "lab_id": 1,
            "computer_id": None,
            "action_type": "HARDWARE_REPAIR",
            "duration_min": 25,
            "details": "Replaced faulty DP cable on student desk Row 3 and cleaned cabinet ventilation fans.",
            "status": "Resolved"
        }

        res = self.client.post("/api/technician/log", json=log_payload, headers={"X-CSRFToken": self.csrf_token})
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertTrue(data["success"])
        log_id = data["log_id"]

        # Verify entry in DB
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM TECHNICIAN_LOGS WHERE id = ?", (log_id,))
            entry = cursor.fetchone()
            self.assertIsNotNone(entry)
            self.assertEqual(entry["action_type"], "HARDWARE_REPAIR")
            self.assertEqual(entry["duration_min"], 25)
        finally:
            conn.close()

    def test_09_unauthorized_access_protection(self):
        """Verify student or unauthenticated users are restricted from remote admin commands and technician logging."""
        unauth_client = self.app.test_client()

        # Unauthenticated Remote Admin Exec
        res1 = unauth_client.post("/api/admin/remote-exec", json={
            "pc_number": "DL-ADMIN-01",
            "command": "systeminfo"
        }, headers={"X-CSRFToken": "invalid_token"})
        self.assertIn(res1.status_code, [401, 403])

        # Unauthenticated Technician Log
        res2 = unauth_client.post("/api/technician/log", json={
            "lab_id": 1,
            "action_type": "CABLE_FIX",
            "details": "Unauthorized note"
        }, headers={"X-CSRFToken": "invalid_token"})
        self.assertIn(res2.status_code, [401, 403])


if __name__ == "__main__":
    unittest.main()
