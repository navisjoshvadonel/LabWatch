# College Lab PC Fault Reporting System (LabPulse)

LabPulse is an end-to-end, network-aware PC fault reporting and monitoring platform built across three architectural tiers:
- **Data Tier (Step 1)**: Relational SQLite database (`labpulse.db`) with Write-Ahead Logging (WAL) and indexed inventory.
- **Network Tier (Step 2)**: Core C protocols for **ICMP** fault detection, **UDP** Wake-on-LAN remote restarts, and **TCP** server alerts.
- **Application Tier (Step 3)**: Unified Python Flask Core Server with Auth, Ticketing Engine (Data Validation & CRUD), Automated Ticket Handling, and a rich **Single-Page Application (SPA)** web portal.

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
│   └── index.html            # Unified Single-Page Application (SPA) dashboard (Dark theme)
├── bin/
│   └── labpulse_monitor.exe  # Compiled high-performance C binary
├── python_server.py          # Flask Core Server (Auth, Tickets, Automated Alert Handler, SPA)
├── build.bat / Makefile      # Automated build scripts for Windows and Linux
├── computers_monitor.txt     # Target inventory dynamically consumed by C daemon
├── labpulse.db               # SQLite database (WAL mode enabled)
├── schema.sql                # DDL database schema with performance indexes
├── setup_db.py               # Database setup, seeding, and monitor exporter
└── PROJECT_REPORT.md         # Comprehensive engineering report
```

---

## Features Implemented in Step 3

1. **Auth Service**:
   - `POST /api/auth/login`: Authenticates students, staff, technicians, and admins using SHA-256 hashed passwords.
   - `POST /api/auth/register`: Role-based account creation with input validation.
   - `GET /api/auth/me` & `POST /api/auth/logout`: Session management and live role switching.

2. **Ticketing Engine**:
   - `POST /api/tickets`: CRUD operations with **Data Validation**:
     - Enforces non-empty mandatory fields.
     - **Verifies PC matches the selected lab**: Enforces `computer.lab_id == request.lab_id` to prevent cross-lab mismatches.
     - Auto-generates unique Ticket ID (`TCK-xxx`), initial `"Pending"` status, and timestamp.
   - `GET /api/tickets`: Filters by status, lab, user, priority with oldest-first triage ordering.
   - `PUT /api/tickets/<id>`: Technician triage, status transitions (`In Progress`, `Resolved`), notes, and `resolved_at` timestamps.

3. **Automated Ticket Handling (C to Python Pipeline)**:
   - `POST /api/pc-status`: Listens for offline alerts from the C daemon.
   - When the C daemon reports that **PC-30** (or any workstation) has timed out, Python updates the database and **automatically creates a Critical 'Network Down' ticket on the dashboard** in real time!

4. **Unified Single-Page Application (SPA)**:
   - Accessible at `http://127.0.0.1:5000/`.
   - **No disjointed individual pages**: Live workstation monitor grid, ticket triage, issue reporting, and live C telemetry feed in one fluid reactive interface.

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

