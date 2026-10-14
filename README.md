# LabWatch — Laboratory PC Fault Reporting & Monitoring System

**Mepco Schlenk Engineering College, Sivakasi — Department of Artificial Intelligence and Data Science (AIDS)**  
*Developed by venki and navi*

LabWatch is an end-to-end, network-aware PC fault reporting and monitoring platform built across three architectural tiers:
- **Data Tier (Step 1)**: Relational SQLite database (`labpulse.db`) with Write-Ahead Logging (WAL) and indexed inventory.
- **Network Tier (Step 2)**: Core C protocols for **ICMP** fault detection, **UDP** Wake-on-LAN remote restarts, and **TCP** server alerts.
- **Application Tier (Step 3 & 4)**: Unified Python Flask Core Server with Role-Based Access Control (Student vs IT Admin), Ticketing Engine, Automated Resolution Workflows, and institutionally branded responsive portals.

---

## System Architecture & Protocols

```text
├── c_src/
│   ├── common.h              # Shared cross-platform socket headers & structures
│   ├── icmp.h / icmp.c       # [ICMP] Fault detection (RFC 792 Echo Request, Checksum, Raw Sockets)
│   ├── udp.h / udp.c         # [UDP]  Remote Restart (Wake-on-LAN Magic Packet via IPPROTO_UDP)
│   ├── tcp.h / tcp.c         # [TCP]  Dynamic alert bridge (HTTP POST via stream socket to Python)
│   └── main.c                # Daemon orchestrator & CLI entry point
├── static/
│   ├── favicon.ico           # Official institutional browser favicon
│   └── mepco_logo.svg        # Scalable vector institutional logo
├── templates/
│   ├── admin.html            # IT Staff Administration, SMTP Configuration & Triage Hub
│   ├── index.html            # Unified SPA (Live Grid, Digital Twin, Triage, Exam Mode, Analytics)
│   ├── login.html            # Institutional Authentication Portal
│   ├── nba_naac_register.html # NBA Criterion 6 & NAAC 4.4 Equipment Maintenance Register
│   ├── qr_stickers.html      # 246-Workstation Printable Physical QR Code Sticker Sheet
│   ├── report.html           # Student Fault Reporting Form with Fast Chips & AI Lab Doctor
│   └── status.html           # Public ticket self-tracking status page
├── tests/                    # Comprehensive Automated Test Suites (72 tests)
│   ├── test_aids_realtime_solving.py
│   ├── test_college_deployment_readiness.py
│   ├── test_college_deployment_upgrades.py
│   ├── test_edge_case_failures.py
│   ├── test_hod_report_and_discovery.py
│   ├── test_institutional_security_hardening.py
│   ├── test_live_gmail_smtp_protocol.py
│   ├── test_phase_a_security.py
│   └── test_zero_phone_college_reporting.py
├── backups/                  # Automated SQLite online VACUUM snapshot directory
├── bin/
│   └── .gitkeep              # Binary directory placeholder
├── python_server.py          # Flask & Waitress WSGI Server (Auth, Tickets, Alerts, Snapshots)
├── event_broker.py           # Real-Time Server-Sent Events (SSE) Live Stream Pub/Sub Broker
├── ai_diagnostic.py          # AI Lab Doctor (Domain NLP & Root Cause Analysis Engine)
├── remediation_engine.py     # 1-Click Self-Healing Playbooks, L3/L4 Diagnostics & Pre-Exam Audit
├── qr_generator.py           # Pure-Python Vector SVG QR Code Mobile Reporting Generator
├── build.bat / Makefile      # Automated build scripts for Windows and Linux
├── deploy_labwatch.ps1       # Production PowerShell institutional deployer
├── deploy_student_desktop_shortcut.bat # 1-Click Student Workstation Desktop Shortcut Deployer
├── start_labwatch.bat        # One-click Windows deployment launcher
├── report_issue.bat          # Workstation desktop zero-phone issue reporter
├── computers_monitor.txt     # Target inventory dynamically consumed by C daemon
├── computers_monitor.csv     # Workstation inventory CSV export
├── labpulse.db               # SQLite database (WAL mode enabled)
├── schema.sql                # DDL database schema with performance indexes
├── setup_db.py               # Database setup, seeding, and monitor exporter
├── requirements.txt          # Python application & testing dependencies
├── .gitattributes            # Line ending normalization & binary rules
├── .gitignore                # Git ignore rules for caches, secrets, and logs
└── PROJECT_REPORT.md         # Comprehensive engineering report
```

---

## AIDS Department Real-Time Solving Capabilities

1. **High-Performance Server-Sent Events (SSE) Push Stream (`/api/stream/events`)**:
   - Sub-millisecond live push notifications for PC state changes, ticket filings, and triage actions.
   - Integrated Web Audio API institutional alert chimes.

2. **Domain-Specific AI Lab Doctor (`/api/ai/diagnose`)**:
   - Curricular NLP engine diagnosing PyTorch CUDA OOM, Jupyter deadlocks, and proxy timeouts.
   - Provides immediate student self-help advice and tags tickets with 1-click remediation playbooks.

3. **Automated Self-Healing Playbooks (`/api/remediate`)**:
   - `kill_ai_zombies`: Terminates hung PyTorch/CUDA/Jupyter workers and frees GPU VRAM.
   - `network_self_heal`: Flushes DNS, renews DHCP lease, and audits gateway ping.
   - `disk_scratch_purge`: Removes HuggingFace lockfiles and scratch temp space.
   - `service_restart`: Restarts JupyterLab (8888) and SSH daemons.
   - `wol_restart`: Dual-broadcast Wake-on-LAN via compiled C program.

4. **Pre-Lab & Practical Exam Readiness Engine (`/api/exam-readiness`)**:
   - Parallel multi-threaded health check of all PCs in a lab in <2 seconds.
   - Official printable **Department Lab Readiness Audit Certificate**.

5. **AIDS Department Digital Twin (Interactive Floor Plan)**:
   - Visual row-by-row layout of all 6 departmental laboratories with click-to-remediate drawer.

6. **Native Vector SVG QR Code Generator (`/api/pc-qr/<pc_id>`)**:
   - Scan physical QR stickers on monitors to prefill and report issues in 5 seconds.

7. **Designated Master Admin Consoles & 246 Workstation Matrix**:
   - 60 Workstations in flagship labs (Deep Learning Lab AI-201, Machine Learning Lab AI-202).
   - 30 Workstations in specialized labs (Data Science AI-101, Gen AI AI-301, Data Analytics AI-102, Language Processing AI-302).
   - Elevated Instructor Dais / Master Admin Console in each lab (`DL-ADMIN-01` to `LP-ADMIN-01`).

8. **Universal Cross-Lab Remote Admin Terminal (`/api/admin/remote-exec`)**:
   - Authenticated lab admins can execute live diagnostics (`ping`, `nvidia-smi`, `systeminfo`, `netstat`, `service status`, `traceroute`) on any workstation across any lab with sub-millisecond execution telemetry.

9. **HOD Executive Daily Dossier & Technician Timesheet (`/api/reports/daily`)**:
   - Day-by-day accountability ledger recording technician service notes, tickets resolved, playbooks executed, and lab MTTR.
   - Includes printable institutional report with Head of Department signature block and one-click CSV export (`/api/reports/daily/export`).

10. **Zero-Hardcoding Adaptive LAN & Subnet Auto-Discovery (`/api/computers/discover`)**:
    - Dynamically scans ARP tables and lab subnets, registers newly connected workstations, updates heartbeats, and re-syncs C daemon monitoring target files without restarting binaries.

11. **Printable Workstation QR Code Physical Sticker Sheet (`/print-qr-stickers`)**:
    - One-click print-ready sheet generating institutional QR labels for all 246 workstations across all 6 department labs or single-lab batches.
    - Designed with `@media print` CSS for standard A4 sticker paper to affix directly onto student workstation monitors.

12. **College Deployment Pre-Flight Health & Posture Telemetry (`/api/deployment/status`)**:
    - Comprehensive system verification reporting SQLite WAL mode, database integrity check, C binary compilation, campus gateway reachability, active LAN interfaces, and security lockouts.

13. **NBA Criterion 6 & NAAC Key Indicator 4.4 Equipment Down-Time & Maintenance Register (`/admin/reports/nba-naac-register`)**:
    - Official academic accreditation audit register documenting Mean Time To Repair (MTTR), equipment breakdown frequencies, and servicing history.
    - Includes one-click CSV export (`/api/reports/nba-naac-register?format=csv`) and institutional printable letterhead with 3-tier signature block (Lab In-Charge, HOD, Principal/Dean).

14. **Real-Time Telegram Bot Mobile Technician Dispatch (`/api/admin/telegram/config`)**:
    - Instant mobile notification broadcast to laboratory technician smartphones on new critical/high tickets and ticket resolutions without reliance on external SMS gateways.

15. **Zero-Downtime Hot Online Database Snapshots (`/api/admin/database/backup`)**:
    - Instant point-in-time database snapshots using SQLite `VACUUM INTO` with automated 10-file rolling rotation.

16. **Enterprise WSGI Production Runner (`waitress`)**:
    - Multi-threaded production WSGI server (`waitress` with 16 threads) for campus-wide concurrency, with automatic Werkzeug fallback for development.

17. **1-Click Student Workstation Desktop Shortcut Deployer (`deploy_student_desktop_shortcut.bat`)**:
    - Automated batch deployer creating a zero-friction desktop shortcut on `C:\Users\Public\Desktop` with auto-detected client IP.

---

## Quick Start & Running

### 1. Build the C Daemon
```bash
.\build.bat
```

### 2. Start the Application Core Server
```bash
# Windows Batch Launcher (Automated Pre-Flight & Browser Launch):
.\start_labwatch.bat

# Or Modern PowerShell Launcher:
.\deploy_labwatch.ps1

# Or Direct Python Execution (Starts Waitress WSGI Production Server):
python python_server.py 5000
```
Open **`http://127.0.0.1:5000`** in any browser to access the live dashboard.
Workstations across the campus lab LAN can access directly via **`http://<CAMPUS_LAN_IP>:5000`**.

### 3. Key Portal Endpoints
- **Live Digital Twin & Remediation Hub**: `http://127.0.0.1:5000/monitor`
- **Student Fault Reporting Form**: `http://127.0.0.1:5000/report`
- **IT Admin Triage Dashboard**: `http://127.0.0.1:5000/admin`
- **NBA/NAAC Accreditation Maintenance Register**: `http://127.0.0.1:5000/admin/reports/nba-naac-register`
- **Workstation QR Physical Label Sheet**: `http://127.0.0.1:5000/print-qr-stickers`
- **Deployment Posture Health API**: `http://127.0.0.1:5000/api/deployment/status`

### 4. Trigger C Protocol Daemon & Automated Ticket Creation
```bash
# Ping PC-30 (detects timeout and alerts Python via TCP):
.\bin\labpulse_monitor.exe --ping-pc PC-30

# Send Wake-on-LAN Remote Restart via UDP to PC-30:
.\bin\labpulse_monitor.exe --restart PC-30

# Dispatch alert triggering automated ticket creation for any workstation:
.\bin\labpulse_monitor.exe --notify PC-20 offline

# Full inventory ICMP sweep:
.\bin\labpulse_monitor.exe --sweep
```

