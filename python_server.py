#!/usr/bin/env python3
"""
python_server.py
College Lab PC Fault Reporting System (LabPulse)
Application Tier Core Server (Flask) - Steps 3–5 Implementation

Features:
  1. Auth Service: Login, Registration, Session verification (SHA-256 password hash).
  2. Ticketing Engine: Full CRUD with Data Validation (empty fields, PC matches lab, unique TCK-ID).
  3. Automated Ticket Handling: Listens for alerts from C program (POST /api/pc-status).
     When PC-30 ping times out, automatically spawns a 'Network Down' ticket on admin dashboard.
  4. Remote Action: WoL Remote Restart execution (UDP broadcast).
  5. Telemetry & Live Activity stream for real-time monitoring.
  6. Unified Single-Page Application (SPA) web portal on '/' (no individual pages).
  7. Step 5 - Output & Notifications (Phase 4 Resolution & Feedback):
     - Database Update: Ticket status Pending -> Resolved with resolved_at timestamp.
     - Automated Email Notification: smtplib SMTP email dispatched to reporter on resolution.
     - UI Update: Green 'Resolved' badges propagated via /api/notifications/status polling.
     - Archiving: Resolved tickets retained in SQLite for hardware lifespan analysis.
     - Reporter Status View: /status/<ticket_number> page for self-check of ticket state.
"""

import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import re
import secrets
import smtplib
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
import threading
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import wraps
from flask import Flask, request, jsonify, render_template, session, redirect, url_for

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "labpulse.db")
BIN_PATH = os.path.join(BASE_DIR, "bin", "labpulse_monitor.exe")
LOG_PATH = os.path.join(BASE_DIR, "labpulse.log")

# ==============================================================================
# 1. STRUCTURED LOGGING ENGINE (CONSOLE + ROTATING FILE LOG)
# ==============================================================================
logger = logging.getLogger("LabPulse")
logger.setLevel(logging.INFO)

log_formatter = logging.Formatter(
    "[%(asctime)s] [%(levelname)s] [%(threadName)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

if not logger.handlers:
    # Console stdout stream handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_formatter)
    logger.addHandler(console_handler)

    # Rotating file log handler (max 5MB, 3 historical backups)
    file_handler = RotatingFileHandler(LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(log_formatter)
    logger.addHandler(file_handler)

# ==============================================================================
# 2. FLASK APPLICATION & SESSION SECURITY CONFIGURATION
# ==============================================================================
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"), static_folder=os.path.join(BASE_DIR, "static"))
app.secret_key = os.environ.get("LABPULSE_SECRET_KEY", "labpulse_secret_key_mepco_aids_secure_2026")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["TEMPLATES_AUTO_RELOAD"] = True

# ==============================================================================
# 3. CSRF PROTECTION ENGINE
# ==============================================================================
def get_csrf_token() -> str:
    """Retrieve or generate cryptographically secure CSRF token for active session."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]

@app.context_processor
def inject_csrf_token():
    """Exposes csrf_token() to all Jinja templates automatically."""
    return dict(csrf_token=get_csrf_token)

CSRF_EXEMPT_PATHS = {
    "/api/pc-status",  # Dedicated machine-to-machine TCP bridge called by C daemon
}

@app.before_request
def csrf_protect():
    """Verify CSRF token on all state-changing HTTP methods (POST, PUT, DELETE, PATCH)."""
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        if request.path in CSRF_EXEMPT_PATHS:
            return None

        # Allow initial login/register if token not yet loaded from session
        token = (
            request.headers.get("X-CSRFToken") or
            request.headers.get("X-CSRF-Token") or
            request.form.get("csrf_token")
        )
        if not token and request.is_json:
            token = (request.get_json(silent=True) or {}).get("csrf_token")

        session_token = session.get("csrf_token")
        if not session_token:
            session_token = get_csrf_token()

        # If it's a login attempt from a fresh browser session without existing session state, allow
        if request.path in ("/api/auth/login", "/api/auth/register", "/login") and not token:
            return None

        if not token or not secrets.compare_digest(token, session_token):
            logger.warning(f"[-] [CSRF Reject] Blocked unauthorized {request.method} to {request.path} from {request.remote_addr}")
            if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"error": "Security validation failed: CSRF token missing or invalid. Please refresh the page."}), 403
            return render_template("login.html", error="Security validation (CSRF) failed. Please refresh and try again.", portal="student"), 403

# ==============================================================================
# 4. BACKGROUND ICMP SWEEP THREAD (NO MANUAL C DAEMON START NEEDED)
# ==============================================================================
class BackgroundSweepThread(threading.Thread):
    """
    Periodically executes compiled C binary (bin/labpulse_monitor.exe --sweep).
    Runs on a timer thread and automatically triggers the C layer monitoring.
    """
    def __init__(self, interval_seconds: int = 30):
        super().__init__(name="LabPulse-ICMPSweep", daemon=True)
        self.interval = interval_seconds
        self._stop_event = threading.Event()
        self.last_sweep_ts = None

    def stop(self):
        self._stop_event.set()

    def run(self):
        logger.info(f"[+] Background ICMP Sweep engine started (Interval: {self.interval}s)")
        time.sleep(3)  # Brief delay to allow Flask server to bind first
        while not self._stop_event.is_set():
            if os.path.exists(BIN_PATH):
                try:
                    logger.info(f"[*] Running automated ICMP sweep via {BIN_PATH}...")
                    proc = subprocess.run(
                        [BIN_PATH, "--sweep"],
                        capture_output=True,
                        text=True,
                        timeout=25,
                        cwd=BASE_DIR
                    )
                    self.last_sweep_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    logger.info(f"[+] Automated ICMP sweep completed at {self.last_sweep_ts}")
                except subprocess.TimeoutExpired:
                    logger.warning("[-] Automated ICMP sweep subprocess timed out after 25s")
                except Exception as exc:
                    logger.error(f"[-] Automated ICMP sweep error: {exc}")
            else:
                logger.debug(f"[-] C binary {BIN_PATH} not yet available; sweep sleeping.")

            for _ in range(self.interval):
                if self._stop_event.is_set():
                    break
                time.sleep(1)

sweep_thread = None

def start_background_sweep():
    global sweep_thread
    auto_sweep_enabled = os.environ.get("LABPULSE_AUTO_SWEEP", "1") == "1"
    if auto_sweep_enabled and (sweep_thread is None or not sweep_thread.is_alive()):
        interval = int(os.environ.get("LABPULSE_SWEEP_INTERVAL", "30"))
        sweep_thread = BackgroundSweepThread(interval_seconds=interval)
        sweep_thread.start()

# ==============================================================================
# STEP 5: SMTP EMAIL NOTIFICATION CONFIGURATION
# ==============================================================================
# Uses Python's built-in smtplib with Gmail SMTP over TLS (port 587).
# For demonstration / evaluation: uses Gmail App Password (no OAuth required).
# In production: load from environment variables or a secrets vault.
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587                               # STARTTLS port (RFC 3207)
SMTP_SENDER_EMAIL = "labpulse.mepco@gmail.com"  # Sender identity shown to recipients
SMTP_SENDER_NAME  = "LabPulse | Mepco IT Support"
# App password (16-char, spaces stripped). Set LABPULSE_SMTP_PASSWORD env var for security.
SMTP_APP_PASSWORD = os.environ.get("LABPULSE_SMTP_PASSWORD", "demo_mode_no_real_send")
# When True, email is built and logged but NOT actually sent (safe for offline demos)
SMTP_DEMO_MODE = (SMTP_APP_PASSWORD == "demo_mode_no_real_send")

# In-memory notification log for UI badge and recent-activity display
notification_log: list = []

# In-memory telemetry circular buffer for live activity stream
telemetry_events = []


def add_telemetry(event_type: str, message: str, details: dict = None):
    """Log live activity for the telemetry dashboard."""
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": event_type,
        "message": message,
        "details": details or {}
    }
    telemetry_events.insert(0, entry)
    if len(telemetry_events) > 100:
        telemetry_events.pop()


# ==============================================================================
# STEP 5: AUTOMATED EMAIL NOTIFICATION ENGINE (smtplib)
# ==============================================================================

def _build_resolution_email_html(ticket_number: str, reporter_name: str,
                                  pc_number: str, lab_name: str,
                                  issue_category: str, description: str,
                                  resolution_notes: str, resolved_at: str) -> str:
    """Build a rich-HTML 'PC Fixed' email body using inline CSS (email-safe)."""
    return f"""
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;padding:24px 0;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0"
             style="background:#ffffff;border-radius:8px;border:1px solid #e2e8f0;
                    box-shadow:0 2px 8px rgba(0,0,0,.06);overflow:hidden;">

        <!-- Header Bar -->
        <tr>
          <td style="background:#0066b3;padding:24px 32px;">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td>
                  <div style="color:#ffffff;font-size:20px;font-weight:800;
                              letter-spacing:-0.01em;line-height:1.2;">LabPulse</div>
                  <div style="color:#93c5fd;font-size:12px;font-weight:600;margin-top:2px;">
                    Mepco Schlenk Engineering College &mdash; IT Support Portal
                  </div>
                </td>
                <td align="right">
                  <span style="background:#16a34a;color:#ffffff;font-size:13px;
                               font-weight:700;padding:6px 14px;border-radius:999px;">
                    ✅ Issue Resolved
                  </span>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Body -->
        <tr>
          <td style="padding:32px 32px 24px;">
            <p style="margin:0 0 8px;color:#0f172a;font-size:16px;font-weight:600;">
              Dear {reporter_name},
            </p>
            <p style="margin:0 0 24px;color:#475569;font-size:14px;line-height:1.6;">
              Your reported laboratory computer fault has been <strong>inspected and fully resolved</strong>
              by Mepco IT Support staff. Your workstation is now back online and ready for use.
            </p>

            <!-- Ticket Detail Card -->
            <table width="100%" cellpadding="0" cellspacing="0"
                   style="background:#f1f5f9;border-radius:6px;border:1px solid #e2e8f0;
                          margin-bottom:24px;">
              <tr><td style="padding:20px 24px;">
                <div style="font-size:11px;font-weight:700;color:#64748b;
                            text-transform:uppercase;letter-spacing:.05em;
                            margin-bottom:12px;">Resolution Summary</div>
                <table width="100%" cellpadding="0" cellspacing="0">
                  <tr>
                    <td style="padding:5px 0;color:#64748b;font-size:13px;width:140px;">Ticket Number</td>
                    <td style="padding:5px 0;">
                      <span style="font-family:'Courier New',monospace;font-size:13px;
                                   font-weight:700;color:#0b2545;
                                   background:#e0e7ff;padding:2px 8px;
                                   border-radius:4px;">{ticket_number}</span>
                    </td>
                  </tr>
                  <tr>
                    <td style="padding:5px 0;color:#64748b;font-size:13px;">Workstation</td>
                    <td style="padding:5px 0;color:#0f172a;font-size:13px;font-weight:600;">{pc_number}</td>
                  </tr>
                  <tr>
                    <td style="padding:5px 0;color:#64748b;font-size:13px;">Laboratory</td>
                    <td style="padding:5px 0;color:#0f172a;font-size:13px;">{lab_name}</td>
                  </tr>
                  <tr>
                    <td style="padding:5px 0;color:#64748b;font-size:13px;">Issue Category</td>
                    <td style="padding:5px 0;color:#0f172a;font-size:13px;">{issue_category}</td>
                  </tr>
                  <tr>
                    <td style="padding:5px 0;color:#64748b;font-size:13px;">Description</td>
                    <td style="padding:5px 0;color:#475569;font-size:13px;">{description}</td>
                  </tr>
                  <tr>
                    <td style="padding:5px 0;color:#64748b;font-size:13px;">Resolved At</td>
                    <td style="padding:5px 0;color:#15803d;font-size:13px;font-weight:600;">{resolved_at}</td>
                  </tr>
                  <tr>
                    <td style="padding:5px 0;color:#64748b;font-size:13px;vertical-align:top;">Technician Notes</td>
                    <td style="padding:5px 0;color:#0f172a;font-size:13px;">{resolution_notes}</td>
                  </tr>
                </table>
              </td></tr>
            </table>

            <p style="margin:0 0 8px;color:#475569;font-size:13px;line-height:1.6;">
              If you experience any further issues with this workstation, please submit a new
              fault report at the LabPulse portal.
            </p>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="background:#f8fafc;border-top:1px solid #e2e8f0;
                     padding:16px 32px;text-align:center;">
            <p style="margin:0;color:#94a3b8;font-size:11px;line-height:1.5;">
              &copy; 2026 Mepco Schlenk Engineering College (Autonomous), Sivakasi.<br>
              Department of Artificial Intelligence &amp; Data Science (AiDS) &mdash;
              LabPulse / LabWatch Automated Notification System.
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>
"""


def send_resolution_email(
    to_email: str,
    reporter_name: str,
    ticket_number: str,
    pc_number: str,
    lab_name: str,
    issue_category: str,
    description: str,
    resolution_notes: str,
    resolved_at: str
) -> dict:
    """
    Step 5: Automated Email Notification using Python's built-in smtplib.
    Connects to Gmail SMTP over STARTTLS (port 587, RFC 3207) and sends a
    rich-HTML 'PC Fixed' email to the student who reported the issue.

    When SMTP_DEMO_MODE is True (no real password), the email is built and
    logged in notification_log but not transmitted — safe for offline demos.
    """
    subject = f"[LabPulse] Your Ticket {ticket_number} — PC Fault Resolved ✅"
    html_body = _build_resolution_email_html(
        ticket_number, reporter_name, pc_number, lab_name,
        issue_category, description, resolution_notes, resolved_at
    )

    # Build MIME message
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"{SMTP_SENDER_NAME} <{SMTP_SENDER_EMAIL}>"
    msg["To"]      = to_email
    msg["X-LabPulse-Ticket"] = ticket_number

    # Plain-text fallback
    plain_text = (
        f"Dear {reporter_name},\n\n"
        f"Your fault report for workstation {pc_number} in {lab_name} "
        f"(Ticket: {ticket_number}) has been resolved by IT Staff.\n\n"
        f"Category   : {issue_category}\n"
        f"Description: {description}\n"
        f"Resolved At: {resolved_at}\n"
        f"Notes      : {resolution_notes}\n\n"
        f"Mepco Schlenk Engineering College — LabPulse Notification System"
    )
    msg.attach(MIMEText(plain_text, "plain", "utf-8"))
    msg.attach(MIMEText(html_body,  "html",  "utf-8"))

    result = {
        "ticket_number": ticket_number,
        "to_email": to_email,
        "reporter": reporter_name,
        "subject": subject,
        "pc_number": pc_number,
        "lab_name": lab_name,
        "sent": False,
        "demo_mode": SMTP_DEMO_MODE,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "error": None
    }

    if SMTP_DEMO_MODE:
        # Demo mode: log without transmitting so the project works offline
        result["sent"] = True
        result["note"] = (
            "DEMO MODE: Email built successfully (HTML + plain-text MIME) but not "
            "transmitted. Set LABPULSE_SMTP_PASSWORD env var to enable live dispatch."
        )
        logger.info(f"[+] [EMAIL DEMO] 'PC Fixed' notification for {ticket_number} → {to_email} (demo, not transmitted)")
    else:
        try:
            # Establish STARTTLS connection to Gmail SMTP
            ctx = ssl.create_default_context()
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                server.ehlo()
                server.starttls(context=ctx)   # Upgrade to encrypted channel
                server.ehlo()
                server.login(SMTP_SENDER_EMAIL, SMTP_APP_PASSWORD)
                server.sendmail(SMTP_SENDER_EMAIL, [to_email], msg.as_string())
            result["sent"] = True
            logger.info(f"[+] [EMAIL SENT] Ticket {ticket_number} resolution email → {to_email}")
        except smtplib.SMTPAuthenticationError:
            result["error"] = "SMTP authentication failed. Check app password."
            logger.error(f"[-] [EMAIL ERROR] Auth failed for {ticket_number}: {result['error']}")
        except smtplib.SMTPException as e:
            result["error"] = f"SMTP error: {e}"
            logger.error(f"[-] [EMAIL ERROR] {ticket_number}: {result['error']}")
        except Exception as e:
            result["error"] = f"Unexpected error: {e}"
            logger.error(f"[-] [EMAIL ERROR] {ticket_number}: {result['error']}")

    # Archive in in-memory notification log (circular buffer, max 50)
    notification_log.insert(0, result)
    if len(notification_log) > 50:
        notification_log.pop()

    return result


def _send_email_async(to_email, reporter_name, ticket_number, pc_number,
                      lab_name, issue_category, description,
                      resolution_notes, resolved_at):
    """Fire-and-forget wrapper so email dispatch never blocks an HTTP response."""
    try:
        send_resolution_email(
            to_email, reporter_name, ticket_number, pc_number, lab_name,
            issue_category, description, resolution_notes, resolved_at
        )
    except Exception as exc:
        logger.error(f"[-] [EMAIL THREAD] Unhandled exception: {exc}")


def get_db_connection():
    """Establish high-performance SQLite connection with Write-Ahead Logging (WAL)."""
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def ensure_schema_migrations():
    """Ensure database schema has the 'salt' column in USERS and all required indices."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(USERS)")
        cols = [c[1] for c in cursor.fetchall()]
        if cols and "salt" not in cols:
            logger.info("[*] Auto-migrating USERS table: adding 'salt' column...")
            cursor.execute("ALTER TABLE USERS ADD COLUMN salt TEXT NOT NULL DEFAULT ''")
            conn.commit()

        # Generate cryptographic salt for any existing users with empty salt
        cursor.execute("SELECT id, username, password_hash, salt FROM USERS WHERE salt IS NULL OR salt = ''")
        unmigrated = cursor.fetchall()
        for u in unmigrated:
            new_salt = secrets.token_hex(16)
            cursor.execute("UPDATE USERS SET salt = ? WHERE id = ?", (new_salt, u["id"]))
        if unmigrated:
            conn.commit()
            logger.info(f"[+] Migrated {len(unmigrated)} existing user records with unique cryptographic salts.")
    except Exception as exc:
        logger.error(f"[-] Schema migration check failed: {exc}")
    finally:
        conn.close()


def hash_password(password: str, salt: str = None) -> tuple:
    """Hash password using SHA-256 with per-user cryptographic salt."""
    if not salt:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return pwd_hash, salt


def verify_password(password: str, stored_hash: str, salt: str = None) -> bool:
    """Constant-time verification of password against stored hash with salt."""
    if not stored_hash or not password:
        return False
    if salt:
        computed_hash = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
        if secrets.compare_digest(computed_hash, stored_hash):
            return True
    # Legacy unsalted check fallback
    legacy_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return secrets.compare_digest(legacy_hash, stored_hash)


def send_wol_packet(mac_address: str, broadcast_ip: str = "255.255.255.255", port: int = 9) -> bool:
    """Send UDP Wake-on-LAN Magic Packet directly via socket or compiled C binary."""
    try:
        clean_mac = mac_address.replace(":", "").replace("-", "")
        if len(clean_mac) != 12:
            return False
        mac_bytes = bytes.fromhex(clean_mac)
        magic_payload = b"\xFF" * 6 + mac_bytes * 16

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(magic_payload, (broadcast_ip, port))
        return True
    except Exception as e:
        logger.error(f"[-] WoL Python dispatch error: {e}")
        return False


# ==============================================================================
# 1. AUTHENTICATION SERVICE
# ==============================================================================

@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    """Authenticate student, staff, technician, or administrator using salted SHA-256."""
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash, salt, full_name, email, role FROM USERS WHERE username = ?", (username,))
        user = cursor.fetchone()

        user_salt = user["salt"] if (user and "salt" in user.keys()) else None
        if not user or not verify_password(password, user["password_hash"], user_salt):
            logger.warning(f"[-] Unauthorized login attempt for user '{username}' from {request.remote_addr}")
            return jsonify({"error": "Invalid username or password"}), 401

        # Seamlessly upgrade legacy unsalted passwords on successful login
        if user_salt is None or user_salt == "":
            new_hash, new_salt = hash_password(password)
            cursor.execute("UPDATE USERS SET password_hash = ?, salt = ? WHERE id = ?", (new_hash, new_salt, user["id"]))
            conn.commit()
            logger.info(f"[+] Transparently upgraded legacy password for '{username}' to salted SHA-256.")

        user_data = {
            "id": user["id"],
            "username": user["username"],
            "full_name": user["full_name"],
            "email": user["email"],
            "role": user["role"]
        }
        session["user"] = user_data
        session.permanent = True  # Enforce session expiration policy
        get_csrf_token()          # Seed session CSRF token

        logger.info(f"[+] User '{username}' logged in successfully as [{user['role']}]")
        add_telemetry("AUTH_LOGIN", f"User '{username}' logged in successfully as [{user['role']}]", user_data)

        return jsonify({
            "success": True,
            "message": f"Welcome back, {user['full_name']}!",
            "user": user_data
        }), 200
    finally:
        conn.close()


@app.route("/api/auth/register", methods=["POST"])
def auth_register():
    """Register a new student, staff, or technician account with salted SHA-256."""
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    full_name = data.get("full_name", "").strip()
    email = data.get("email", "").strip()
    role = data.get("role", "student").strip().lower()

    # Validation
    if not username or not password or not full_name or not email:
        return jsonify({"error": "All fields (username, password, full_name, email) are required"}), 400

    if role not in ("student", "staff", "technician", "admin"):
        return jsonify({"error": "Invalid role selected"}), 400

    if len(password) < 4:
        return jsonify({"error": "Password must be at least 4 characters"}), 400

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # Check if username or email already exists
        cursor.execute("SELECT id FROM USERS WHERE username = ? OR email = ?", (username, email))
        if cursor.fetchone():
            return jsonify({"error": "Username or email is already registered"}), 409

        pwd_hash, salt = hash_password(password)
        cursor.execute(
            """
            INSERT INTO USERS (username, password_hash, salt, full_name, email, role)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (username, pwd_hash, salt, full_name, email, role)
        )
        conn.commit()
        new_id = cursor.lastrowid

        user_data = {
            "id": new_id,
            "username": username,
            "full_name": full_name,
            "email": email,
            "role": role
        }
        session["user"] = user_data
        session.permanent = True
        get_csrf_token()

        logger.info(f"[+] User '{username}' registered successfully with cryptographic salt as [{role}]")
        add_telemetry("AUTH_REGISTER", f"New user '{username}' registered as [{role}]", user_data)

        return jsonify({
            "success": True,
            "message": "Account created successfully",
            "user": user_data
        }), 201
    except sqlite3.Error as e:
        conn.rollback()
        logger.error(f"[-] Registration error: {e}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()


@app.route("/api/auth/me", methods=["GET"])
def auth_me():
    """Return currently authenticated user session or default student profile."""
    if "user" in session:
        return jsonify({"authenticated": True, "user": session["user"]})
    return jsonify({"authenticated": False, "user": None})


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    """End active user session."""
    user = session.pop("user", None)
    if user:
        add_telemetry("AUTH_LOGOUT", f"User '{user['username']}' logged out")
    return jsonify({"success": True, "message": "Logged out successfully"})


# ==============================================================================
# 2. TICKETING ENGINE (CRUD & DATA VALIDATION)
# ==============================================================================

@app.route("/api/tickets", methods=["GET"])
def get_tickets():
    """
    Retrieve tickets with optional filtering by status, lab, user, priority.
    Sorts by reported_at ASC (oldest first for technician triage) or custom.
    """
    status_filter = request.args.get("status")
    lab_filter = request.args.get("lab_id")
    user_filter = request.args.get("user_id")
    priority_filter = request.args.get("priority")
    sort_order = request.args.get("sort", "ASC").upper()

    query = """
        SELECT t.id, t.ticket_number, t.user_id, t.lab_id, t.computer_id,
               t.issue_category, t.description, t.status, t.priority,
               t.reported_at, t.resolved_at, t.technician_id, t.resolution_notes,
               u.full_name AS reporter_name, u.email AS reporter_email, u.role AS reporter_role,
               tech.full_name AS technician_name,
               l.lab_name, l.location AS lab_location,
               c.pc_number, c.ip_address, c.mac_address, c.status AS pc_status
        FROM TICKETS t
        JOIN USERS u ON t.user_id = u.id
        LEFT JOIN USERS tech ON t.technician_id = tech.id
        JOIN LABS l ON t.lab_id = l.id
        JOIN COMPUTERS c ON t.computer_id = c.id
        WHERE 1=1
    """
    params = []

    if status_filter and status_filter.lower() != "all":
        query += " AND t.status = ?"
        params.append(status_filter)

    if lab_filter and lab_filter.lower() != "all":
        if str(lab_filter).isdigit():
            query += " AND t.lab_id = ?"
            params.append(int(lab_filter))
        else:
            query += " AND l.lab_name LIKE ?"
            params.append(f"%{lab_filter}%")

    if priority_filter and priority_filter.lower() != "all":
        query += " AND t.priority = ?"
        params.append(priority_filter.capitalize())

    if user_filter:
        query += " AND t.user_id = ?"
        params.append(int(user_filter))

    safe_sort = "DESC" if sort_order == "DESC" else "ASC"
    query += f" ORDER BY t.reported_at {safe_sort}"

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = [dict(r) for r in cursor.fetchall()]
        return jsonify({"count": len(rows), "tickets": rows})
    finally:
        conn.close()


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """
    Returns real-time aggregated KPI statistics for dashboard live-updating:
    {pending, resolved, offline, online, total_computers, timestamp}
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM TICKETS WHERE status = 'Pending'")
        pending = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM TICKETS WHERE status IN ('Resolved', 'Closed')")
        resolved = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM COMPUTERS WHERE status IN ('Offline', 'Faulty')")
        offline = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM COMPUTERS WHERE status = 'Online'")
        online = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM COMPUTERS")
        total = cursor.fetchone()[0]

        return jsonify({
            "pending": pending,
            "resolved": resolved,
            "offline": offline,
            "online": online,
            "total_computers": total,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 200
    finally:
        conn.close()


@app.route("/api/tickets", methods=["POST"])
def create_ticket():
    """
    Create a new fault ticket with Data Validation:
      1. Checking empty fields (user_id, lab_id, computer_id, issue_category, description).
      2. Verifying that the chosen computer actually belongs to the selected lab.
      3. Database insertion with unique Ticket ID (TCK-xxx), 'Pending' status, timestamp.
    """
    data = request.get_json() or {}

    user_id = data.get("user_id") or (session.get("user", {}).get("id") if "user" in session else 2) # Default Navis Joshva (id=2)
    lab_id = data.get("lab_id")
    computer_id = data.get("computer_id")
    issue_category = data.get("issue_category", "").strip()
    description = data.get("description", "").strip()
    priority = data.get("priority", "Medium").strip().capitalize()

    # 1. Validate empty fields
    if not lab_id:
        return jsonify({"error": "Validation Error: Laboratory selection is required"}), 400
    if not computer_id:
        return jsonify({"error": "Validation Error: Workstation computer selection is required"}), 400
    if not issue_category:
        return jsonify({"error": "Validation Error: Issue Category is required"}), 400
    if not description or len(description) < 5:
        return jsonify({"error": "Validation Error: Please provide a descriptive summary (at least 5 characters)"}), 400

    valid_categories = {
        "Network Connectivity", "Operating System", "Hardware Fault",
        "Peripheral / Display", "Software Crash", "Power Issue", "Other"
    }
    if issue_category not in valid_categories:
        return jsonify({"error": f"Invalid category. Must be one of: {', '.join(sorted(valid_categories))}"}), 400

    if priority not in ("Low", "Medium", "High", "Critical"):
        priority = "Medium"

    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        # 2. DATA VALIDATION: Verify PC matches the selected lab
        cursor.execute("SELECT id, lab_id, pc_number, ip_address, status FROM COMPUTERS WHERE id = ?", (computer_id,))
        comp = cursor.fetchone()
        if not comp:
            return jsonify({"error": f"Validation Error: Computer ID #{computer_id} does not exist in inventory"}), 400

        if int(comp["lab_id"]) != int(lab_id):
            cursor.execute("SELECT lab_name FROM LABS WHERE id = ?", (comp["lab_id"],))
            actual_lab = cursor.fetchone()
            actual_lab_name = actual_lab["lab_name"] if actual_lab else f"Lab #{comp['lab_id']}"
            return jsonify({
                "error": f"Validation Error: {comp['pc_number']} is assigned to '{actual_lab_name}', not the selected lab!"
            }), 400

        # Verify user exists
        cursor.execute("SELECT id, full_name, username FROM USERS WHERE id = ?", (user_id,))
        reporter = cursor.fetchone()
        if not reporter:
            return jsonify({"error": f"User #{user_id} not found"}), 400

        # 3. Generate unique Ticket Number (e.g. TCK-104)
        cursor.execute("SELECT MAX(id) FROM TICKETS")
        max_id_row = cursor.fetchone()
        next_id = (max_id_row[0] or 100) + 1
        ticket_number = f"TCK-{next_id}"

        # 4. Insert ticket
        cursor.execute(
            """
            INSERT INTO TICKETS (
                ticket_number, user_id, lab_id, computer_id,
                issue_category, description, status, priority, reported_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 'Pending', ?, CURRENT_TIMESTAMP)
            """,
            (ticket_number, user_id, int(lab_id), int(computer_id), issue_category, description, priority)
        )
        conn.commit()
        created_ticket_id = cursor.lastrowid

        ticket_details = {
            "id": created_ticket_id,
            "ticket_number": ticket_number,
            "pc_number": comp["pc_number"],
            "lab_id": lab_id,
            "category": issue_category,
            "priority": priority,
            "status": "Pending",
            "reporter": reporter["full_name"]
        }
        add_telemetry("TICKET_CREATED", f"Ticket '{ticket_number}' filed on {comp['pc_number']} by {reporter['full_name']}", ticket_details)

        return jsonify({
            "success": True,
            "message": f"Ticket {ticket_number} logged successfully",
            "ticket": ticket_details
        }), 201

    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()


@app.route("/api/tickets/<int:ticket_id>", methods=["PUT"])
def update_ticket(ticket_id: int):
    """
    Update ticket status, assign technician, and record resolution notes.
    """
    data = request.get_json() or {}
    status = data.get("status")
    technician_id = data.get("technician_id")
    resolution_notes = data.get("resolution_notes")

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, ticket_number, status, computer_id FROM TICKETS WHERE id = ?", (ticket_id,))
        ticket = cursor.fetchone()
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404

        updates = []
        params = []

        if status:
            if status not in ("Pending", "In Progress", "Resolved", "Closed"):
                return jsonify({"error": "Invalid status value"}), 400
            updates.append("status = ?")
            params.append(status)

            if status in ("Resolved", "Closed"):
                updates.append("resolved_at = CURRENT_TIMESTAMP")

        if technician_id is not None:
            updates.append("technician_id = ?")
            params.append(technician_id if technician_id > 0 else None)

        if resolution_notes is not None:
            updates.append("resolution_notes = ?")
            params.append(resolution_notes)

        if not updates:
            return jsonify({"error": "No update fields provided"}), 400

        params.append(ticket_id)
        query = f"UPDATE TICKETS SET {', '.join(updates)} WHERE id = ?"
        cursor.execute(query, params)
        conn.commit()

        add_telemetry("TICKET_UPDATED", f"Ticket '{ticket['ticket_number']}' status updated to [{status or ticket['status']}]", {
            "ticket_id": ticket_id,
            "status": status,
            "notes": resolution_notes
        })

        return jsonify({"success": True, "message": f"Ticket {ticket['ticket_number']} updated successfully"})
    finally:
        conn.close()


@app.route("/api/tickets/<int:ticket_id>", methods=["DELETE"])
def delete_ticket(ticket_id: int):
    """Delete a ticket."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM TICKETS WHERE id = ?", (ticket_id,))
        conn.commit()
        add_telemetry("TICKET_DELETED", f"Ticket #{ticket_id} removed")
        return jsonify({"success": True, "message": f"Ticket #{ticket_id} deleted"})
    finally:
        conn.close()


# ==============================================================================
# 3. AUTOMATED TICKET HANDLING (C DAEMON INTEGRATION)
# ==============================================================================

@app.route("/api/pc-status", methods=["POST"])
def receive_c_daemon_alert():
    """
    Listens for ICMP heartbeat and fault alerts from C daemon:
    Payload: {"pc_id": "PC-30", "status": "offline", "ip_address": "...", "mac_address": "..."}

    When C detects a PC is frozen/offline:
      1. Updates COMPUTERS table (status='Offline', last_heartbeat=CURRENT_TIMESTAMP).
      2. If workstation is frozen/offline (e.g. PC-30 scenario):
         Automatically checks if active ticket exists, and if not,
         INSTANTLY creates a 'Network Down' ticket on the admin dashboard!
    """
    data = request.get_json() or {}
    pc_id = data.get("pc_id")
    status = data.get("status", "offline")
    ip_address = data.get("ip_address")
    mac_address = data.get("mac_address")

    if not pc_id:
        return jsonify({"error": "Missing 'pc_id' parameter in telemetry payload"}), 400

    valid_statuses = {"online": "Online", "offline": "Offline", "faulty": "Faulty", "maintenance": "Maintenance"}
    canonical_status = valid_statuses.get(status.lower(), "Offline")

    t_start = time.perf_counter()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # Find workstation
        cursor.execute("SELECT id, lab_id, pc_number, ip_address, mac_address, status FROM COMPUTERS WHERE pc_number = ?", (pc_id,))
        comp = cursor.fetchone()

        if not comp and ip_address:
            cursor.execute("SELECT id, lab_id, pc_number, ip_address, mac_address, status FROM COMPUTERS WHERE ip_address = ?", (ip_address,))
            comp = cursor.fetchone()

        if not comp:
            return jsonify({"error": f"Workstation '{pc_id}' not recognized in database"}), 404

        comp_id = comp["id"]
        lab_id = comp["lab_id"]
        pc_number = comp["pc_number"]
        old_status = comp["status"]

        # 1. Update status and heartbeat in database
        cursor.execute(
            """
            UPDATE COMPUTERS 
            SET status = ?, last_heartbeat = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (canonical_status, comp_id)
        )
        conn.commit()
        db_ms = (time.perf_counter() - t_start) * 1000.0

        created_ticket_number = None
        action_msg = f"Status updated from '{old_status}' to '{canonical_status}'"

        # 2. AUTOMATED TICKET HANDLING FOR FROZEN/OFFLINE WORKSTATION (PC-30 Scenario)
        if canonical_status in ("Offline", "Faulty"):
            # DEBOUNCE WINDOW (15-min): check active tickets OR tickets reported/resolved within the last 15 minutes
            cursor.execute(
                """
                SELECT id, ticket_number, status, reported_at, resolved_at 
                FROM TICKETS 
                WHERE computer_id = ?
                  AND (
                    status IN ('Pending', 'In Progress')
                    OR (status IN ('Resolved', 'Closed') AND datetime(resolved_at, '+15 minutes') > datetime('now'))
                    OR (datetime(reported_at, '+15 minutes') > datetime('now'))
                  )
                ORDER BY id DESC LIMIT 1
                """,
                (comp_id,)
            )
            existing_ticket = cursor.fetchone()

            if not existing_ticket:
                # Generate new Ticket ID
                cursor.execute("SELECT MAX(id) FROM TICKETS")
                max_row = cursor.fetchone()
                next_id = (max_row[0] or 100) + 1
                ticket_number = f"TCK-{next_id}"

                ticket_desc = (
                    f"Automated Alert: Workstation {pc_number} (IP: {comp['ip_address']}) ping timed out. "
                    f"Machine is frozen / network down. Requires technician inspection or Remote WoL Restart."
                )

                cursor.execute(
                    """
                    INSERT INTO TICKETS (
                        ticket_number, user_id, lab_id, computer_id,
                        issue_category, description, status, priority, reported_at
                    )
                    VALUES (?, 1, ?, ?, 'Network Connectivity', ?, 'Pending', 'Critical', CURRENT_TIMESTAMP)
                    """,
                    (ticket_number, lab_id, comp_id, ticket_desc)
                )
                conn.commit()
                created_ticket_number = ticket_number
                action_msg = f"Offline detected! Automated 'Network Down' ticket {ticket_number} created on dashboard."

                logger.info(f"[+] [AUTOMATED TICKET] Created {ticket_number} for {pc_number} ({comp['ip_address']})")
                add_telemetry("AUTOMATED_TICKET", action_msg, {
                    "pc_id": pc_number,
                    "ticket_number": ticket_number,
                    "ip": comp["ip_address"],
                    "priority": "Critical"
                })
            else:
                action_msg = (
                    f"Offline detected on {pc_number}. Suppressed duplicate ticket: "
                    f"Ticket {existing_ticket['ticket_number']} ({existing_ticket['status']}) "
                    f"is active or was updated within the 15-minute debounce window."
                )
                logger.info(f"[*] [Debounce Active] {action_msg}")

        add_telemetry("ICMP_ALERT", f"C Daemon reported {pc_number} as [{canonical_status}]", {
            "pc_id": pc_number,
            "status": canonical_status,
            "latency_ms": round(db_ms, 3)
        })

        return jsonify({
            "success": True,
            "pc_id": pc_number,
            "previous_status": old_status,
            "current_status": canonical_status,
            "action": action_msg,
            "automated_ticket_created": bool(created_ticket_number),
            "ticket_number": created_ticket_number,
            "db_query_time_ms": round(db_ms, 3)
        }), 200

    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()


# ==============================================================================
# 4. REMOTE ACTION PROTOCOL (Wake-on-LAN Remote Restart)
# ==============================================================================

@app.route("/api/restart", methods=["POST"])
def trigger_remote_restart():
    """
    Trigger Remote Restart (WoL Magic Packet) for a frozen workstation.
    Can be initiated by technician/admin from the dashboard.
    """
    data = request.get_json() or {}
    pc_id = data.get("pc_id")
    computer_id = data.get("computer_id")
    mac_address = data.get("mac_address")

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if not mac_address:
            if pc_id:
                cursor.execute("SELECT id, pc_number, mac_address, ip_address FROM COMPUTERS WHERE pc_number = ?", (pc_id,))
            elif computer_id:
                cursor.execute("SELECT id, pc_number, mac_address, ip_address FROM COMPUTERS WHERE id = ?", (computer_id,))
            else:
                return jsonify({"error": "Provide pc_id or computer_id"}), 400

            comp = cursor.fetchone()
            if not comp:
                return jsonify({"error": "Computer not found"}), 404
            mac_address = comp["mac_address"]
            pc_id = comp["pc_number"]

        # Broadcast WoL magic packet via compiled C program
        c_output = ""
        c_executed = False
        sent = False

        if os.path.exists(BIN_PATH) and pc_id:
            try:
                proc = subprocess.run(
                    [BIN_PATH, "--restart", pc_id],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    cwd=BASE_DIR
                )
                c_output = proc.stdout.strip()
                if proc.returncode == 0:
                    sent = True
                    c_executed = True
            except Exception as e:
                logger.error(f"[-] Subprocess C execution failed: {e}")

        # Fallback to Python socket if C binary was not run
        if not sent:
            sent = send_wol_packet(mac_address)

        if sent:
            method_desc = "Compiled C Daemon (bin/labpulse_monitor.exe)" if c_executed else "Python UDP Socket"
            add_telemetry("WOL_RESTART", f"[{method_desc}] Broadcasted WoL Magic Packet to {pc_id} (MAC: {mac_address})", {
                "target_pc": pc_id,
                "mac": mac_address,
                "c_output": c_output
            })
            return jsonify({
                "success": True,
                "message": f"Wake-on-LAN Magic Packet broadcasted to {pc_id} ({mac_address}) via UDP:9 using {method_desc}",
                "target_pc": pc_id,
                "target_mac": mac_address,
                "c_executed": c_executed,
                "c_output": c_output
            }), 200
        else:
            return jsonify({"error": "Failed to transmit WoL Magic Packet"}), 500
    finally:
        conn.close()


# ==============================================================================
# 5. LABS, COMPUTERS & TELEMETRY APIS
# ==============================================================================

@app.route("/api/labs", methods=["GET"])
def get_labs():
    """List all physical laboratories."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, lab_name, department, location, total_pcs FROM LABS ORDER BY id ASC")
        return jsonify({"labs": [dict(r) for r in cursor.fetchall()]})
    finally:
        conn.close()


@app.route("/api/computers", methods=["GET"])
def get_computers():
    """List computers, optionally filtered by lab_id."""
    lab_id = request.args.get("lab_id")
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if lab_id and lab_id != "all":
            cursor.execute(
                """
                SELECT c.id, c.lab_id, c.pc_number, c.ip_address, c.mac_address,
                       c.status, c.specs, c.last_heartbeat, l.lab_name
                FROM COMPUTERS c
                JOIN LABS l ON c.lab_id = l.id
                WHERE c.lab_id = ?
                ORDER BY c.id ASC
                """,
                (int(lab_id),)
            )
        else:
            cursor.execute(
                """
                SELECT c.id, c.lab_id, c.pc_number, c.ip_address, c.mac_address,
                       c.status, c.specs, c.last_heartbeat, l.lab_name
                FROM COMPUTERS c
                JOIN LABS l ON c.lab_id = l.id
                ORDER BY c.id ASC
                """
            )
        return jsonify({"computers": [dict(r) for r in cursor.fetchall()]})
    finally:
        conn.close()


@app.route("/api/telemetry", methods=["GET"])
def get_telemetry():
    """Fetch live activity stream."""
    return jsonify({"events": telemetry_events})


@app.route("/api/health", methods=["GET"])
def get_health():
    """Server and database health metrics."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode;")
        journal = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM COMPUTERS;")
        pc_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM TICKETS WHERE status = 'Pending';")
        pending_tickets = cursor.fetchone()[0]

        cursor.execute("SELECT status, COUNT(*) as count FROM COMPUTERS GROUP BY status;")
        pc_statuses = {r["status"]: r["count"] for r in cursor.fetchall()}

        return jsonify({
            "status": "Healthy",
            "server": "Flask / LabPulse Application Tier",
            "database_mode": journal.upper(),
            "total_computers": pc_count,
            "status_breakdown": pc_statuses,
            "pending_tickets": pending_tickets,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    finally:
        conn.close()


# ==============================================================================
# AUTHENTICATION & ROLE-BASED ACCESS CONTROL MIDDLEWARE
# ==============================================================================

def login_required(roles=None):
    """
    Role-based authentication decorator:
    - Verifies 'user' in session.
    - If unauthenticated, redirects to /login with error and appropriate portal tab.
    - If roles specified and user role not in roles:
      - Student/Staff attempting /admin -> redirects to /report with warning
      - Otherwise -> redirects to /login with error
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = session.get("user")
            if not user:
                if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                    return jsonify({"error": "Authentication required. Please sign in."}), 401
                portal = "admin" if roles and all(r in ("admin", "technician") for r in roles) else "student"
                return redirect(url_for("login_page", portal=portal, error="Authentication required. Please sign in first."))
            if roles and user.get("role") not in roles:
                if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                    return jsonify({"error": "Access Denied: Insufficient administrative privileges."}), 403
                if user.get("role") in ("student", "staff"):
                    return redirect(url_for("user_issue_reporting", error="Access Denied: IT Staff administrative privileges required."))
                return redirect(url_for("login_page", error="Access Denied: Insufficient authorization."))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route("/login", methods=["GET"])
def login_page():
    """Serves the split Student / IT Admin login portal."""
    user = session.get("user")
    if user:
        if user.get("role") in ("admin", "technician"):
            return redirect(url_for("admin_dashboard"))
        else:
            return redirect(url_for("user_issue_reporting"))

    portal = request.args.get("portal", "student")
    error  = request.args.get("error", "")
    msg    = request.args.get("msg", "")
    return render_template("login.html", portal=portal, error=error, msg=msg)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    """End active user session."""
    user = session.pop("user", None)
    if user:
        add_telemetry("AUTH_LOGOUT", f"User '{user['username']}' logged out")
    return redirect(url_for("login_page", msg="You have been successfully signed out."))


@app.route("/")
def index():
    """
    Role-based entry point:
    - Unauthenticated -> Redirects to /login
    - Student / Staff -> Redirects to /report
    - Admin / Technician -> Redirects to /admin
    """
    user = session.get("user")
    if not user:
        return redirect(url_for("login_page"))
    if user.get("role") in ("admin", "technician"):
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("user_issue_reporting"))


@app.route("/monitor")
@login_required(roles=["admin", "technician"])
def live_monitor():
    """Serves the unified Single-Page Application (SPA) dashboard for IT administrators."""
    return render_template("index.html")


# ==============================================================================
# 7. STEP 4: CLIENT TIER & DASHBOARD ROUTES (HTML/JS + PYTHON JINJA)
# ==============================================================================

@app.route("/report", methods=["GET", "POST"])
@login_required(roles=["student", "staff", "technician", "admin"])
def user_issue_reporting():
    """
    Step 4: User Issue Reporting Form (Phase 1 Input).
    - Basic web page with dropdowns for Lab Room, PC number, and issue category.
    - When user clicks 'Submit Request', it sends a POST request to Python server.
    - Performs Data Validation (empty fields, PC belongs to selected lab).
    - Database insertion with unique Ticket ID, 'Pending' status, timestamp.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        # Load laboratories (6 AI/Data labs)
        cursor.execute("SELECT id, lab_name, location, department, total_pcs FROM LABS ORDER BY id ASC")
        labs = [dict(r) for r in cursor.fetchall()]

        # Load workstations
        cursor.execute("""
            SELECT c.id, c.lab_id, c.pc_number, c.ip_address, c.mac_address, c.status, l.lab_name
            FROM COMPUTERS c
            JOIN LABS l ON c.lab_id = l.id
            ORDER BY c.lab_id ASC, c.id ASC
        """)
        computers = [dict(r) for r in cursor.fetchall()]

        # Group workstations by lab_id for dynamic client dropdown filtering
        computers_by_lab = {}
        for comp in computers:
            lid = str(comp["lab_id"])
            if lid not in computers_by_lab:
                computers_by_lab[lid] = []
            computers_by_lab[lid].append({
                "id": comp["id"],
                "pc_number": comp["pc_number"],
                "ip_address": comp["ip_address"],
                "mac_address": comp["mac_address"],
                "status": comp["status"]
            })

        success_ticket = None
        error_message = request.args.get("error")

        if request.method == "POST":
            data = request.get_json() if request.is_json else request.form.to_dict()

            current_user = session.get("user") or {}
            lab_id_raw = data.get("lab_id")
            pc_raw = data.get("pc_number") or data.get("computer_id")
            issue_category = (data.get("issue_category") or "").strip()
            description = (data.get("description") or "").strip()
            reporter_name = (data.get("reporter_name") or current_user.get("full_name") or "Student Reporter").strip()
            priority = (data.get("priority") or "Medium").strip().capitalize()

            # Data Validation
            if not lab_id_raw:
                error_message = "Validation Error: Please select a Laboratory Room."
            elif not pc_raw:
                error_message = "Validation Error: Please select a Workstation PC number."
            elif not issue_category:
                error_message = "Validation Error: Please select an Issue Category."
            else:
                try:
                    lab_id = int(lab_id_raw)
                except ValueError:
                    lab_id = None

                # Locate computer and verify assignment to selected lab
                cursor.execute(
                    "SELECT id, lab_id, pc_number, ip_address, status FROM COMPUTERS WHERE (id = ? OR pc_number = ?) AND lab_id = ?",
                    (pc_raw, pc_raw, lab_id)
                )
                comp = cursor.fetchone()

                if not comp:
                    cursor.execute(
                        "SELECT c.pc_number, l.lab_name FROM COMPUTERS c JOIN LABS l ON c.lab_id = l.id WHERE c.id = ? OR c.pc_number = ?",
                        (pc_raw, pc_raw)
                    )
                    mismatch = cursor.fetchone()
                    if mismatch:
                        error_message = f"Validation Error: {mismatch['pc_number']} belongs to '{mismatch['lab_name']}', not the selected room!"
                    else:
                        error_message = f"Validation Error: Workstation '{pc_raw}' does not exist in inventory."
                else:
                    computer_id = comp["id"]
                    pc_num = comp["pc_number"]
                    if not description:
                        description = f"Fault reported on {pc_num} in {comp['status']} state: {issue_category}"

                    # Reporter user ID (Navis Joshva = id 2 default)
                    user_id = session.get("user", {}).get("id") or 2

                    # Unique Ticket ID generation (TCK-xxx)
                    cursor.execute("SELECT MAX(id) FROM TICKETS")
                    max_id = (cursor.fetchone()[0] or 100) + 1
                    ticket_number = f"TCK-{max_id}"

                    cursor.execute(
                        """
                        INSERT INTO TICKETS (
                            ticket_number, user_id, lab_id, computer_id,
                            issue_category, description, status, priority, reported_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, 'Pending', ?, CURRENT_TIMESTAMP)
                        """,
                        (ticket_number, user_id, lab_id, computer_id, issue_category, description, priority)
                    )
                    conn.commit()

                    cursor.execute("SELECT lab_name FROM LABS WHERE id = ?", (lab_id,))
                    lab_row = cursor.fetchone()
                    lab_name = lab_row["lab_name"] if lab_row else "Selected Lab"

                    success_ticket = {
                        "ticket_number": ticket_number,
                        "lab_name": lab_name,
                        "pc_number": pc_num,
                        "issue_category": issue_category,
                        "description": description,
                        "priority": priority,
                        "status": "Pending",
                        "reported_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "reporter": reporter_name
                    }
                    add_telemetry("TICKET_CREATED", f"[Client Form] Ticket {ticket_number} submitted for {pc_num} in {lab_name}", success_ticket)

                    if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                        return jsonify({"success": True, "ticket": success_ticket, "message": "Ticket logged successfully!"})

        if error_message and (request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest"):
            return jsonify({"error": error_message}), 400

        return render_template(
            "report.html",
            labs=labs,
            computers=computers,
            computers_by_lab=computers_by_lab,
            computers_by_lab_json=json.dumps(computers_by_lab),
            success_ticket=success_ticket,
            error_message=error_message,
            logged_user=session.get("user")
        )
    finally:
        conn.close()


@app.route("/admin", methods=["GET"])
@login_required(roles=["admin", "technician"])
def admin_dashboard():
    """
    Step 4: Admin Dashboard (Phase 3 Action - IT Staff View).
    - Python runs a SELECT query on the database and passes data to this HTML page.
    - Displays pending tickets oldest first (ORDER BY reported_at ASC).
    - Includes 'Mark as Resolved' button.
    - Includes 'Remote Restart' button for offline PCs executing the compiled C program (Wake-on-LAN).
    """
    restarted_pc = request.args.get("restarted_pc")
    resolved_id = request.args.get("resolved_id")
    c_output = request.args.get("c_output")
    status_msg = request.args.get("msg")

    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        # 1. SELECT query: Pending tickets, OLDEST FIRST (ORDER BY reported_at ASC)
        cursor.execute("""
            SELECT t.id, t.ticket_number, t.user_id, t.lab_id, t.computer_id,
                   t.issue_category, t.description, t.status, t.priority,
                   t.reported_at, t.resolved_at,
                   u.full_name AS reporter_name, u.email AS reporter_email,
                   l.lab_name, l.location AS lab_location,
                   c.pc_number, c.ip_address, c.mac_address, c.status AS pc_status
            FROM TICKETS t
            JOIN USERS u ON t.user_id = u.id
            JOIN LABS l ON t.lab_id = l.id
            JOIN COMPUTERS c ON t.computer_id = c.id
            WHERE t.status = 'Pending'
            ORDER BY t.reported_at ASC
        """)
        pending_tickets = [dict(r) for r in cursor.fetchall()]

        # 2. SELECT query: Offline/Faulty PCs for Remote Restart
        cursor.execute("""
            SELECT c.id, c.lab_id, c.pc_number, c.ip_address, c.mac_address,
                   c.status, c.specs, c.last_heartbeat, l.lab_name, l.location
            FROM COMPUTERS c
            JOIN LABS l ON c.lab_id = l.id
            WHERE c.status IN ('Offline', 'Faulty')
            ORDER BY l.id ASC, c.pc_number ASC
        """)
        offline_pcs = [dict(r) for r in cursor.fetchall()]

        # 3. SELECT query: Recently resolved tickets (History)
        cursor.execute("""
            SELECT t.id, t.ticket_number, t.issue_category, t.description, t.status,
                   t.reported_at, t.resolved_at, t.priority,
                   l.lab_name, c.pc_number, u.full_name AS reporter_name
            FROM TICKETS t
            JOIN USERS u ON t.user_id = u.id
            JOIN LABS l ON t.lab_id = l.id
            JOIN COMPUTERS c ON t.computer_id = c.id
            WHERE t.status IN ('Resolved', 'Closed')
            ORDER BY t.resolved_at DESC, t.id DESC
            LIMIT 10
        """)
        resolved_tickets = [dict(r) for r in cursor.fetchall()]

        # 4. Overall statistics
        cursor.execute("SELECT COUNT(*) FROM COMPUTERS")
        total_computers = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM TICKETS WHERE status = 'Pending'")
        pending_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM COMPUTERS WHERE status IN ('Offline', 'Faulty')")
        offline_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM TICKETS WHERE status IN ('Resolved', 'Closed')")
        resolved_count = cursor.fetchone()[0]

        stats = {
            "total_computers": total_computers,
            "pending_count": pending_count,
            "offline_count": offline_count,
            "resolved_count": resolved_count
        }

        return render_template(
            "admin.html",
            pending_tickets=pending_tickets,
            offline_pcs=offline_pcs,
            resolved_tickets=resolved_tickets,
            stats=stats,
            restarted_pc=restarted_pc,
            c_output=c_output,
            status_msg=status_msg,
            logged_user=session.get("user")
        )
    finally:
        conn.close()


@app.route("/admin/resolve/<int:ticket_id>", methods=["POST"])
@login_required(roles=["admin", "technician"])
def admin_resolve_ticket(ticket_id: int):
    """
    Step 4 + Step 5: 'Mark as Resolved' button on Admin Dashboard.

    Phase 4 (Resolution & Feedback) implementation:
    1. DATABASE UPDATE: Sets ticket status Pending -> Resolved, stamps resolved_at = NOW().
    2. AUTOMATED EMAIL NOTIFICATION: Dispatches a 'PC Fixed' HTML email via smtplib to
       the student/staff who originally reported the fault (reporter's email from USERS table).
    3. UI UPDATE: Redirect back to Admin Dashboard where the green 'Resolved' badge is shown;
       notification_log feeds the /api/notifications/status endpoint polled by the UI.
    4. ARCHIVING: Resolved ticket is retained in SQLite (never deleted) for hardware
       lifespan analysis and audit trail.
    """
    notes = request.form.get("notes") or "Issue inspected and verified resolved by IT Support Staff."
    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        # Fetch full ticket details including reporter info for email
        cursor.execute("""
            SELECT t.id, t.ticket_number, t.computer_id, t.lab_id,
                   t.issue_category, t.description, t.status,
                   u.full_name AS reporter_name, u.email AS reporter_email,
                   c.pc_number, l.lab_name
            FROM TICKETS t
            JOIN USERS u ON t.user_id = u.id
            JOIN COMPUTERS c ON t.computer_id = c.id
            JOIN LABS l ON t.lab_id = l.id
            WHERE t.id = ?
        """, (ticket_id,))
        ticket = cursor.fetchone()

        if not ticket:
            return redirect(url_for("admin_dashboard", msg=f"Error: Ticket #{ticket_id} not found"))

        if ticket["status"] == "Resolved":
            return redirect(url_for("admin_dashboard", msg=f"{ticket['ticket_number']} is already Resolved"))

        tck_num        = ticket["ticket_number"]
        comp_id        = ticket["computer_id"]
        reporter_name  = ticket["reporter_name"]
        reporter_email = ticket["reporter_email"]
        pc_number      = ticket["pc_number"]
        lab_name       = ticket["lab_name"]
        issue_category = ticket["issue_category"]
        description    = ticket["description"]

        # ─── 1. DATABASE UPDATE ───────────────────────────────────────────────
        resolved_at_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            """
            UPDATE TICKETS
            SET status           = 'Resolved',
                resolved_at      = CURRENT_TIMESTAMP,
                resolution_notes = ?
            WHERE id = ?
            """,
            (notes, ticket_id)
        )
        # Also mark the computer back Online (fault cleared)
        cursor.execute(
            "UPDATE COMPUTERS SET status = 'Online', last_heartbeat = CURRENT_TIMESTAMP "
            "WHERE id = ? AND status != 'Online'",
            (comp_id,)
        )
        conn.commit()

        # ─── 2. AUTOMATED EMAIL NOTIFICATION (smtplib) ───────────────────────
        # Dispatched in a background thread so HTTP response is instant
        email_thread = threading.Thread(
            target=_send_email_async,
            args=(
                reporter_email, reporter_name, tck_num,
                pc_number, lab_name, issue_category,
                description, notes, resolved_at_ts
            ),
            daemon=True
        )
        email_thread.start()

        # ─── 3. TELEMETRY & NOTIFICATION LOG ─────────────────────────────────
        add_telemetry(
            "TICKET_RESOLVED",
            f"[Step 5] IT Staff resolved {tck_num} | 'PC Fixed' email dispatched to {reporter_email}",
            {
                "ticket_id":     ticket_id,
                "ticket_number": tck_num,
                "pc_number":     pc_number,
                "lab_name":      lab_name,
                "reporter":      reporter_name,
                "email":         reporter_email,
                "notes":         notes,
                "resolved_at":   resolved_at_ts,
                "email_demo":    SMTP_DEMO_MODE
            }
        )

        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json:
            return jsonify({
                "success":       True,
                "message":       f"{tck_num} marked as Resolved. 'PC Fixed' email dispatched to {reporter_email}.",
                "ticket_id":     ticket_id,
                "ticket_number": tck_num,
                "email_sent_to": reporter_email,
                "demo_mode":     SMTP_DEMO_MODE
            })

        return redirect(url_for(
            "admin_dashboard",
            msg=f"✅ Ticket {tck_num} resolved! 'PC Fixed' email sent to {reporter_name} ({reporter_email})."
        ))
    finally:
        conn.close()


@app.route("/admin/restart/<pc_id>", methods=["POST"])
@login_required(roles=["admin", "technician"])
def admin_remote_restart(pc_id: str):
    """
    Step 4: 'Remote Restart' button for offline PCs on Admin Dashboard.
    Python executes the compiled C program (bin/labpulse_monitor.exe --restart <pc_id>)
    to send the Wake-on-LAN magic packet over the network.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, pc_number, mac_address, ip_address, status FROM COMPUTERS WHERE pc_number = ?", (pc_id,))
        comp = cursor.fetchone()
        if not comp:
            return redirect(url_for("admin_dashboard", msg=f"Error: PC {pc_id} not found"))

        mac_address = comp["mac_address"]
        c_output = ""
        c_success = False

        # Execute compiled C program directly
        if os.path.exists(BIN_PATH):
            try:
                proc = subprocess.run(
                    [BIN_PATH, "--restart", pc_id],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    cwd=BASE_DIR
                )
                c_output = proc.stdout.strip()
                if proc.returncode == 0:
                    c_success = True
            except Exception as e:
                c_output = f"Execution exception: {e}"

        # Fallback to Python WoL if C binary is missing
        if not c_success:
            py_sent = send_wol_packet(mac_address)
            if py_sent:
                c_output += "\n[Python WoL fallback dispatched 102-byte UDP packet]"
                c_success = True

        add_telemetry("WOL_RESTART", f"[Admin Dashboard] Remote Restart triggered for {pc_id} (MAC: {mac_address}) via C protocol", {
            "pc_id": pc_id,
            "mac": mac_address,
            "c_output": c_output
        })

        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json:
            return jsonify({
                "success": c_success,
                "pc_id": pc_id,
                "mac": mac_address,
                "c_output": c_output,
                "message": f"Wake-on-LAN magic packet sent to {pc_id} via C program!"
            })

        return redirect(url_for("admin_dashboard", restarted_pc=pc_id, c_output=c_output, msg=f"Remote Restart signal broadcasted to {pc_id}!"))
    finally:
        conn.close()



# ==============================================================================
# 8. STEP 5: OUTPUT & NOTIFICATION ROUTES (Phase 4 Resolution & Feedback)
# ==============================================================================

@app.route("/api/notifications/status", methods=["GET"])
def get_notification_status():
    """
    Step 5: Notification status API endpoint polled by the UI for 'Resolved' badge updates.
    Returns the in-memory notification log (emails dispatched on ticket resolution) so the
    UI can display a live 'PC Fixed' notification indicator without page reload.
    Also queries the database for any newly resolved tickets to confirm green badge state.
    """
    limit = int(request.args.get("limit", 20))
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # Fetch recently resolved tickets for UI badge rendering
        cursor.execute("""
            SELECT t.id, t.ticket_number, t.issue_category, t.status,
                   t.reported_at, t.resolved_at, t.resolution_notes,
                   u.full_name AS reporter_name, u.email AS reporter_email,
                   c.pc_number, l.lab_name
            FROM TICKETS t
            JOIN USERS u ON t.user_id = u.id
            JOIN LABS l ON t.lab_id = l.id
            JOIN COMPUTERS c ON t.computer_id = c.id
            WHERE t.status IN ('Resolved', 'Closed')
            ORDER BY t.resolved_at DESC
            LIMIT ?
        """, (limit,))
        resolved_in_db = [dict(r) for r in cursor.fetchall()]

        # Summary counts
        cursor.execute("SELECT COUNT(*) FROM TICKETS WHERE status = 'Pending'")
        pending_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM TICKETS WHERE status IN ('Resolved', 'Closed')")
        resolved_count = cursor.fetchone()[0]

        return jsonify({
            "pending_count":      pending_count,
            "resolved_count":     resolved_count,
            "smtp_demo_mode":     SMTP_DEMO_MODE,
            "smtp_host":          f"{SMTP_HOST}:{SMTP_PORT}",
            "notifications_sent": len(notification_log),
            "recent_emails":      notification_log[:limit],
            "recently_resolved":  resolved_in_db
        })
    finally:
        conn.close()


@app.route("/status/<ticket_number>", methods=["GET"])
@login_required(roles=["student", "staff", "technician", "admin"])
def reporter_ticket_status(ticket_number: str):
    """
    Step 5: Reporter self-check view for ticket status (Phase 4 UI Update).
    Students who submitted a fault report can visit /status/TCK-104 to see
    whether their ticket has been resolved. If resolved, a green 'Resolved' badge
    is shown along with the technician resolution notes and resolution timestamp.
    Resolved tickets are archived (never deleted) — available for hardware lifespan analysis.
    """
    ticket_number = ticket_number.upper().strip()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT t.id, t.ticket_number, t.issue_category, t.description,
                   t.status, t.priority, t.reported_at, t.resolved_at,
                   t.resolution_notes,
                   u.full_name AS reporter_name, u.email AS reporter_email,
                   c.pc_number, c.ip_address, c.mac_address, c.status AS pc_status,
                   l.lab_name, l.location AS lab_location
            FROM TICKETS t
            JOIN USERS u ON t.user_id = u.id
            JOIN LABS l ON t.lab_id = l.id
            JOIN COMPUTERS c ON t.computer_id = c.id
            WHERE UPPER(t.ticket_number) = ?
        """, (ticket_number,))
        ticket = cursor.fetchone()

        if not ticket:
            return render_template("status.html",
                                   ticket=None,
                                   ticket_number=ticket_number,
                                   error=f"Ticket '{ticket_number}' not found in the system.",
                                   logged_user=session.get("user"))

        return render_template("status.html",
                               ticket=dict(ticket),
                               ticket_number=ticket_number,
                               error=None,
                               logged_user=session.get("user"))
    finally:
        conn.close()


# ==============================================================================
# 9. STANDALONE CLI FALLBACK HANDLER (FOR C SYSTEM CALL INTEGRATION)
# ==============================================================================

def update_pc_status_cli(pc_id: str, status: str, ip_address: str = None, mac_address: str = None) -> bool:
    """Handles C program system call: python python_server.py --report PC-30 offline"""
    valid_statuses = {"online": "Online", "offline": "Offline", "faulty": "Faulty", "maintenance": "Maintenance"}
    canonical_status = valid_statuses.get(status.lower(), "Offline")
    start_time = time.perf_counter()

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, lab_id, pc_number, ip_address, status FROM COMPUTERS WHERE pc_number = ?", (pc_id,))
        row = cursor.fetchone()
        if not row and ip_address:
            cursor.execute("SELECT id, lab_id, pc_number, ip_address, status FROM COMPUTERS WHERE ip_address = ?", (ip_address,))
            row = cursor.fetchone()

        if not row:
            logger.error(f"[-] [CLI Error] Workstation '{pc_id}' not found.")
            return False

        old_status = row["status"]
        comp_id = row["id"]
        lab_id = row["lab_id"]
        pc_num = row["pc_number"]

        cursor.execute("UPDATE COMPUTERS SET status = ?, last_heartbeat = CURRENT_TIMESTAMP WHERE id = ?", (canonical_status, comp_id))
        conn.commit()

        # If offline/frozen, automatically create ticket if none exists
        if canonical_status in ("Offline", "Faulty"):
            cursor.execute("SELECT id FROM TICKETS WHERE computer_id = ? AND status IN ('Pending', 'In Progress')", (comp_id,))
            if not cursor.fetchone():
                cursor.execute("SELECT MAX(id) FROM TICKETS")
                max_id = (cursor.fetchone()[0] or 100) + 1
                tck_num = f"TCK-{max_id}"
                desc = f"Automated Alert: {pc_num} ping timed out. Network down."
                cursor.execute(
                    "INSERT INTO TICKETS (ticket_number, user_id, lab_id, computer_id, issue_category, description, status, priority) VALUES (?, 1, ?, ?, 'Network Connectivity', ?, 'Pending', 'Critical')",
                    (tck_num, lab_id, comp_id, desc)
                )
                conn.commit()
                logger.info(f"[+] [AUTOMATED TICKET] Created {tck_num} for {pc_num}")

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        logger.info(f"[+] [DB UPDATE] Workstation '{pc_num}': '{old_status}' -> '{canonical_status}' (in {elapsed_ms:.2f} ms)")
        return True
    finally:
        conn.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--report":
        pc = sys.argv[2] if len(sys.argv) > 2 else "PC-30"
        st = sys.argv[3] if len(sys.argv) > 3 else "offline"
        ip = sys.argv[4] if len(sys.argv) > 4 else None
        mac = sys.argv[5] if len(sys.argv) > 5 else None
        success = update_pc_status_cli(pc, st, ip, mac)
        sys.exit(0 if success else 1)
    else:
        ensure_schema_migrations()
        start_background_sweep()
        port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
        logger.info(f"[+] Starting LabPulse Flask Core Server at http://127.0.0.1:{port}")
        app.run(host="0.0.0.0", port=port, debug=False)
