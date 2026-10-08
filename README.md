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
├── templates/
│   ├── index.html            # Unified SPA (Live Grid, Digital Twin, Triage, Exam Mode, Analytics)
│   ├── admin.html            # IT Staff Administration & Triage Portal
│   ├── report.html           # User Issue Reporting Form with AI Lab Doctor
│   └── login.html            # Institutional Authentication Portal
├── bin/
│   └── labpulse_monitor.exe  # Compiled high-performance C binary
├── python_server.py          # Flask Core Server (Auth, Tickets, Automated Alert Handler, SPA)
├── event_broker.py           # Real-Time Server-Sent Events (SSE) Live Stream Pub/Sub Broker
├── ai_diagnostic.py          # AI Lab Doctor (Domain NLP & Root Cause Analysis Engine)
├── remediation_engine.py     # 1-Click Self-Healing Playbooks, L3/L4 Diagnostics & Pre-Exam Audit
├── qr_generator.py           # Pure-Python Vector SVG QR Code Mobile Reporting Generator
├── build.bat / Makefile      # Automated build scripts for Windows and Linux
├── computers_monitor.txt     # Target inventory dynamically consumed by C daemon
├── labpulse.db               # SQLite database (WAL mode enabled)
├── schema.sql                # DDL database schema with performance indexes
├── setup_db.py               # Database setup, seeding, and monitor exporter
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

---

## Quick Start & Running

### 1. Build the C Daemon
```bash
.\build.bat
```

### 2. Start the Application Core Server
```bash
python python_server.py 5000
```
Open **`http://127.0.0.1:5000`** in any browser to access the live dashboard.

### 3. Trigger C Protocol Daemon & Automated Ticket Creation
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

