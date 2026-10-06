#!/usr/bin/env python3
"""
================================================================================
College Lab PC Fault Reporting System (LabPulse)
Data Tier Initialization Script: setup_db.py
================================================================================
This script initializes the SQLite database schema and populates it with:
1. LABS: Laboratory rooms (Lab A, Lab B, Lab C)
2. COMPUTERS: Workstation network inventory (IP, MAC, PC Number, Status),
   specifically including PC-30 as required for C monitoring programs.
3. USERS: Authentication records for Students, Staff, Technicians, and Admins.
4. TICKETS: Initial fault tickets (e.g. Ticket #101 on PC-30) for testing.
5. EXPORT: Generates 'computers_monitor.txt' and 'computers_monitor.csv'
   for straightforward reading by C-based network pingers and socket listeners.
================================================================================
"""

import os
import sys
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "labpulse.db")
SCHEMA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")
TXT_EXPORT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "computers_monitor.txt")
CSV_EXPORT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "computers_monitor.csv")


PBKDF2_ITERATIONS = 100_000


def hash_password(password: str, salt: str = None) -> tuple:
    """Hash password using PBKDF2-HMAC-SHA256 with 100,000 iterations and per-user cryptographic salt."""
    if not salt:
        salt = secrets.token_hex(16)
    key_bytes = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ITERATIONS
    )
    pwd_hash = f"pbkdf2:sha256:{PBKDF2_ITERATIONS}${salt}${key_bytes.hex()}"
    return pwd_hash, salt


def get_db_connection(db_path: str = DB_FILE) -> sqlite3.Connection:
    """Establish connection to SQLite database with foreign keys enabled."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn


def initialize_schema(conn: sqlite3.Connection):
    """Execute schema.sql to create LABS, COMPUTERS, USERS, and TICKETS tables."""
    print(f"[*] Initializing database schema from: {SCHEMA_FILE}")
    if os.path.exists(SCHEMA_FILE):
        with open(SCHEMA_FILE, "r", encoding="utf-8") as f:
            schema_sql = f.read()
        conn.executescript(schema_sql)
    else:
        # Fallback embedded schema if schema.sql is not found
        fallback_sql = """
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS LABS (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            lab_name TEXT UNIQUE NOT NULL,
            department TEXT NOT NULL,
            location TEXT NOT NULL,
            total_pcs INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS COMPUTERS (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            lab_id INTEGER NOT NULL,
            pc_number TEXT NOT NULL,
            ip_address TEXT UNIQUE NOT NULL,
            mac_address TEXT UNIQUE NOT NULL,
            status TEXT NOT NULL DEFAULT 'Online',
            specs TEXT,
            last_heartbeat TIMESTAMP,
            ping_history TEXT NOT NULL DEFAULT '[1,1,1,1,1,1,1,1,1,1]',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (lab_id) REFERENCES LABS (id) ON DELETE CASCADE,
            UNIQUE (lab_id, pc_number)
        );

        CREATE TABLE IF NOT EXISTS USERS (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL DEFAULT '',
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('student', 'staff', 'technician', 'admin')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS TICKETS (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_number TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            lab_id INTEGER NOT NULL,
            computer_id INTEGER NOT NULL,
            issue_category TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending',
            priority TEXT NOT NULL DEFAULT 'Medium',
            reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved_at TIMESTAMP,
            technician_id INTEGER,
            resolution_notes TEXT,
            FOREIGN KEY (user_id) REFERENCES USERS (id),
            FOREIGN KEY (lab_id) REFERENCES LABS (id),
            FOREIGN KEY (computer_id) REFERENCES COMPUTERS (id),
            FOREIGN KEY (technician_id) REFERENCES USERS (id)
        );

        CREATE INDEX IF NOT EXISTS idx_computers_lab_id ON COMPUTERS(lab_id);
        CREATE INDEX IF NOT EXISTS idx_computers_ip ON COMPUTERS(ip_address);
        CREATE INDEX IF NOT EXISTS idx_tickets_status ON TICKETS(status);
        CREATE INDEX IF NOT EXISTS idx_tickets_computer_id ON TICKETS(computer_id);
        """
        conn.executescript(fallback_sql)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(USERS)")
    cols = [col[1] for col in cursor.fetchall()]
    if cols and "salt" not in cols:
        print("[*] Migrating USERS table: Adding 'salt' column...")
        cursor.execute("ALTER TABLE USERS ADD COLUMN salt TEXT NOT NULL DEFAULT ''")

    cursor.execute("PRAGMA table_info(COMPUTERS)")
    comp_cols = [col[1] for col in cursor.fetchall()]
    if comp_cols and "ping_history" not in comp_cols:
        print("[*] Migrating COMPUTERS table: Adding 'ping_history' column...")
        cursor.execute("ALTER TABLE COMPUTERS ADD COLUMN ping_history TEXT NOT NULL DEFAULT '[1,1,1,1,1,1,1,1,1,1]'")
        cursor.execute("UPDATE COMPUTERS SET ping_history = '[1,1,1,1,1,1,0,0,0,0]' WHERE status IN ('Offline', 'Faulty')")

    conn.commit()
    print("[+] Database schema successfully created.")


def populate_labs(conn: sqlite3.Connection):
    """Seed LABS table with Mepco AiDS department laboratory rooms."""
    labs_data = [
        ("Deep Learning Lab", "Artificial Intelligence & Data Science", "AiDS Block, 2nd Floor, Room AI-201", 30),
        ("Machine Learning Lab", "Artificial Intelligence & Data Science", "AiDS Block, 2nd Floor, Room AI-202", 30),
        ("Data Science Lab", "Artificial Intelligence & Data Science", "AiDS Block, 1st Floor, Room AI-101", 30),
        ("Gen AI Lab", "Artificial Intelligence & Data Science", "AiDS Block, 3rd Floor, Room AI-301", 30),
        ("Data Analytics Lab", "Artificial Intelligence & Data Science", "AiDS Block, 1st Floor, Room AI-102", 30),
        ("Language Processing Lab", "Artificial Intelligence & Data Science", "AiDS Block, 3rd Floor, Room AI-302", 30),
    ]

    cursor = conn.cursor()
    cursor.executemany(
        """
        INSERT OR IGNORE INTO LABS (lab_name, department, location, total_pcs)
        VALUES (?, ?, ?, ?)
        """,
        labs_data,
    )
    conn.commit()
    print(f"[+] Seeded {len(labs_data)} labs into LABS table.")


def populate_computers(conn: sqlite3.Connection):
    """
    Populate COMPUTERS table with IP and MAC addresses across all 6 AI & Data labs.
    Configures PC-01 to PC-30 for Deep Learning Lab (including PC-30 target for C monitoring),
    PC-01 to PC-30 for Machine Learning Lab, and PC-01 to PC-20 for other departmental labs.
    """
    cursor = conn.cursor()

    # Retrieve Lab IDs
    cursor.execute("SELECT id, lab_name FROM LABS ORDER BY id ASC")
    labs_map = {row["lab_name"]: row["id"] for row in cursor.fetchall()}

    id_dl = labs_map.get("Deep Learning Lab", 1)
    id_ml = labs_map.get("Machine Learning Lab", 2)
    id_ds = labs_map.get("Data Science Lab", 3)
    id_genai = labs_map.get("Gen AI Lab", 4)
    id_da = labs_map.get("Data Analytics Lab", 5)
    id_nlp = labs_map.get("Language Processing Lab", 6)

    computers_data = []

    # 1. Deep Learning Lab (30 PCs, Subnet 192.168.1.x)
    for i in range(1, 31):
        pc_num = f"PC-{i:02d}"
        ip_addr = f"192.168.1.{100 + i}"
        mac_addr = f"00:1A:2B:3C:4D:{i:02X}"
        status = "Faulty" if i == 30 else ("Offline" if i == 15 else "Online")
        specs = "NVIDIA RTX 4090 24GB, Intel Core i9-13900K, 64GB DDR5, 1TB NVMe SSD"
        computers_data.append((id_dl, pc_num, ip_addr, mac_addr, status, specs))

    # 2. Machine Learning Lab (30 PCs, Subnet 192.168.2.x)
    for i in range(1, 31):
        pc_num = f"PC-{i:02d}"
        ip_addr = f"192.168.2.{100 + i}"
        mac_addr = f"00:1B:44:55:6A:{i:02X}"
        status = "Offline" if i == 8 else "Online"
        specs = "NVIDIA RTX 3080 10GB, AMD Ryzen 7 5800X, 32GB DDR4, 512GB NVMe SSD"
        computers_data.append((id_ml, pc_num, ip_addr, mac_addr, status, specs))

    # 3. Data Science Lab (20 PCs, Subnet 192.168.3.x)
    for i in range(1, 21):
        pc_num = f"PC-{i:02d}"
        ip_addr = f"192.168.3.{100 + i}"
        mac_addr = f"00:1C:33:77:8B:{i:02X}"
        status = "Online"
        specs = "Intel Core i7-12700, 32GB RAM, 512GB NVMe SSD"
        computers_data.append((id_ds, pc_num, ip_addr, mac_addr, status, specs))

    # 4. Gen AI Lab (20 PCs, Subnet 192.168.4.x)
    for i in range(1, 21):
        pc_num = f"PC-{i:02d}"
        ip_addr = f"192.168.4.{100 + i}"
        mac_addr = f"00:1D:88:99:AA:{i:02X}"
        status = "Offline" if i == 4 else "Online"
        specs = "NVIDIA A5000 24GB, Intel Xeon W-2245, 64GB ECC RAM, 2TB NVMe"
        computers_data.append((id_genai, pc_num, ip_addr, mac_addr, status, specs))

    # 5. Data Analytics Lab (20 PCs, Subnet 192.168.5.x)
    for i in range(1, 21):
        pc_num = f"PC-{i:02d}"
        ip_addr = f"192.168.5.{100 + i}"
        mac_addr = f"00:1E:AA:BB:CC:{i:02X}"
        status = "Online"
        specs = "Intel Core i7-11700, 16GB DDR4, 512GB NVMe"
        computers_data.append((id_da, pc_num, ip_addr, mac_addr, status, specs))

    # 6. Language Processing Lab (20 PCs, Subnet 192.168.6.x)
    for i in range(1, 21):
        pc_num = f"PC-{i:02d}"
        ip_addr = f"192.168.6.{100 + i}"
        mac_addr = f"00:1F:DD:EE:FF:{i:02X}"
        status = "Offline" if i == 20 else "Online"
        specs = "NVIDIA RTX 4070 Ti, AMD Ryzen 9 7900X, 32GB DDR5, 1TB NVMe"
        computers_data.append((id_nlp, pc_num, ip_addr, mac_addr, status, specs))

    cursor.executemany(
        """
        INSERT OR IGNORE INTO COMPUTERS (lab_id, pc_number, ip_address, mac_address, status, specs)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        computers_data,
    )
    conn.commit()
    print(f"[+] Seeded {len(computers_data)} computers across 6 departmental labs into COMPUTERS table.")


def populate_users(conn: sqlite3.Connection):
    """Seed USERS table with Mepco student team members, staff, and technicians."""
    users_data = [
        # (username, raw_password, full_name, email, role)
        ("admin", "admin123", "System Administrator", "admin@mepcoeng.ac.in", "admin"),
        ("navis", "navis123", "Navis Joshva", "navis@mepcoeng.ac.in", "student"),
        ("venkatraman", "venkat123", "Venkatraman", "venkat@mepcoeng.ac.in", "student"),
        ("gowtham", "gowtham123", "Gowtham", "gowtham@mepcoeng.ac.in", "student"),
        ("keerthana", "keerthana123", "Keerthana", "keerthana@mepcoeng.ac.in", "student"),
        ("nidhes", "nidhes123", "Nidhes", "nidhes@mepcoeng.ac.in", "student"),
        ("tech_rajesh", "tech123", "Rajesh Kumar (Lab Tech)", "rajesh.tech@mepcoeng.ac.in", "technician"),
        ("tech_priya", "tech123", "Priya Sharma (Lab Tech)", "priya.tech@mepcoeng.ac.in", "technician"),
        ("prof_aids", "staff123", "Prof. AiDS Staff Advisor", "hod.aids@mepcoeng.ac.in", "staff"),
    ]

    hashed_users = []
    for username, password, full_name, email, role in users_data:
        pwd_hash, salt = hash_password(password)
        hashed_users.append((username, pwd_hash, salt, full_name, email, role))

    cursor = conn.cursor()
    cursor.executemany(
        """
        INSERT OR IGNORE INTO USERS (username, password_hash, salt, full_name, email, role)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        hashed_users,
    )
    # Ensure all users have updated PBKDF2 hashes
    for username, password, full_name, email, role in users_data:
        cursor.execute("SELECT id, password_hash, salt FROM USERS WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row and (not row["password_hash"].startswith("pbkdf2:sha256:") or not row["salt"]):
            pwd_hash, salt = hash_password(password)
            cursor.execute("UPDATE USERS SET password_hash = ?, salt = ? WHERE id = ?", (pwd_hash, salt, row["id"]))
    conn.commit()
    print(f"[+] Seeded and verified {len(users_data)} users in USERS table with PBKDF2-HMAC-SHA256 (100k rounds).")


def populate_tickets(conn: sqlite3.Connection):
    """
    Seed initial fault tickets demonstrating the workflow:
    - Ticket #101: Pending ticket for PC-30 reported by Navis Joshva in Deep Learning Lab
    - Ticket #102: In-Progress ticket on PC-15 reported by Gowtham in Deep Learning Lab
    - Ticket #103: Resolved ticket on PC-08 reported by Keerthana in Machine Learning Lab
    - Ticket #104: Pending ticket on PC-04 reported by Venkatraman in Gen AI Lab
    - Ticket #105: In-Progress ticket on PC-20 reported by Nidhes in Language Processing Lab
    """
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM USERS WHERE username = 'navis'")
    user_navis = cursor.fetchone()["id"]

    cursor.execute("SELECT id FROM USERS WHERE username = 'gowtham'")
    user_gowtham = cursor.fetchone()["id"]

    cursor.execute("SELECT id FROM USERS WHERE username = 'keerthana'")
    user_keerthana = cursor.fetchone()["id"]

    cursor.execute("SELECT id FROM USERS WHERE username = 'venkatraman'")
    user_venkat = cursor.fetchone()["id"]

    cursor.execute("SELECT id FROM USERS WHERE username = 'nidhes'")
    user_nidhes = cursor.fetchone()["id"]

    cursor.execute("SELECT id FROM USERS WHERE username = 'tech_rajesh'")
    tech_rajesh = cursor.fetchone()["id"]

    cursor.execute("SELECT id FROM LABS WHERE lab_name LIKE '%Deep Learning%'")
    lab_dl = cursor.fetchone()["id"]

    cursor.execute("SELECT id FROM LABS WHERE lab_name LIKE '%Machine Learning%'")
    lab_ml = cursor.fetchone()["id"]

    cursor.execute("SELECT id FROM LABS WHERE lab_name LIKE '%Gen AI%'")
    lab_genai = cursor.fetchone()["id"]

    cursor.execute("SELECT id FROM LABS WHERE lab_name LIKE '%Language Processing%'")
    lab_nlp = cursor.fetchone()["id"]

    cursor.execute("SELECT id FROM COMPUTERS WHERE lab_id = ? AND pc_number = 'PC-30'", (lab_dl,))
    pc_30 = cursor.fetchone()["id"]

    cursor.execute("SELECT id FROM COMPUTERS WHERE lab_id = ? AND pc_number = 'PC-15'", (lab_dl,))
    pc_15 = cursor.fetchone()["id"]

    cursor.execute("SELECT id FROM COMPUTERS WHERE lab_id = ? AND pc_number = 'PC-08'", (lab_ml,))
    pc_08 = cursor.fetchone()["id"]

    cursor.execute("SELECT id FROM COMPUTERS WHERE lab_id = ? AND pc_number = 'PC-04'", (lab_genai,))
    pc_04 = cursor.fetchone()["id"]

    cursor.execute("SELECT id FROM COMPUTERS WHERE lab_id = ? AND pc_number = 'PC-20'", (lab_nlp,))
    pc_20 = cursor.fetchone()["id"]

    now = datetime.now()
    resolved_time = (now - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")

    tickets_data = [
        (
            101,
            "TCK-101",
            user_navis,
            lab_dl,
            pc_30,
            "Network Connectivity",
            "PC-30 cannot obtain an IP address via DHCP and gateway ping fails. Ethernet RJ45 clip appears loose.",
            "Pending",
            "High",
            now.strftime("%Y-%m-%d %H:%M:%S"),
            None,
            None,
            None,
        ),
        (
            102,
            "TCK-102",
            user_gowtham,
            lab_dl,
            pc_15,
            "Hardware Fault",
            "System fails to POST; continuous 3-beep memory alert on power-up during model training.",
            "In Progress",
            "Medium",
            (now - timedelta(hours=5)).strftime("%Y-%m-%d %H:%M:%S"),
            None,
            tech_rajesh,
            "Reseating DDR5 RAM modules in slot DIMM1.",
        ),
        (
            103,
            "TCK-103",
            user_keerthana,
            lab_ml,
            pc_08,
            "Operating System",
            "Ubuntu grub bootloader failed after simulated kernel update.",
            "Resolved",
            "Low",
            (now - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S"),
            resolved_time,
            tech_rajesh,
            "Reinstalled GRUB boot record via Live USB rescue environment. Verified network boot.",
        ),
        (
            104,
            "TCK-104",
            user_venkat,
            lab_genai,
            pc_04,
            "Peripheral / Display",
            "Dual monitor DisplayPort signal flickers intermittently during LLM inference benchmark.",
            "Pending",
            "Medium",
            (now - timedelta(hours=3)).strftime("%Y-%m-%d %H:%M:%S"),
            None,
            None,
            None,
        ),
        (
            105,
            "TCK-105",
            user_nidhes,
            lab_nlp,
            pc_20,
            "Software Crash",
            "PyTorch CUDA out-of-memory kernel panic during transformer tokenization tests.",
            "In Progress",
            "High",
            (now - timedelta(hours=6)).strftime("%Y-%m-%d %H:%M:%S"),
            None,
            tech_rajesh,
            "Reallocated CUDA unified memory and upgraded PyTorch cu121 wheels.",
        ),
    ]

    cursor.executemany(
        """
        INSERT OR IGNORE INTO TICKETS (
            id, ticket_number, user_id, lab_id, computer_id,
            issue_category, description, status, priority,
            reported_at, resolved_at, technician_id, resolution_notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        tickets_data,
    )
    conn.commit()
    print(f"[+] Seeded {len(tickets_data)} tickets into TICKETS table.")


def export_for_c_program(conn: sqlite3.Connection):
    """
    Exports the list of COMPUTERS with IP and MAC addresses to formatted
    text and CSV files so the C monitoring program (ICMP pinger / UDP heartbeat)
    can easily read them without needing complex database link steps.
    """
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT c.id, l.lab_name, c.pc_number, c.ip_address, c.mac_address, c.status
        FROM COMPUTERS c
        JOIN LABS l ON c.lab_id = l.id
        ORDER BY l.id, c.pc_number
        """
    )
    rows = cursor.fetchall()

    # 1. Plain text format for easy C fgets/sscanf:
    # FORMAT: <PC_NUMBER> <IP_ADDRESS> <MAC_ADDRESS> <LAB_NAME>
    with open(TXT_EXPORT_FILE, "w", encoding="utf-8") as f:
        f.write("# LabPulse Computer Monitoring Target List for C Daemon\n")
        f.write("# Format: PC_NUMBER IP_ADDRESS MAC_ADDRESS STATUS LAB_NAME\n")
        for row in rows:
            clean_lab = row["lab_name"].replace(" ", "_")
            f.write(f"{row['pc_number']} {row['ip_address']} {row['mac_address']} {row['status']} {clean_lab}\n")

    # 2. Standard CSV format
    with open(CSV_EXPORT_FILE, "w", encoding="utf-8") as f:
        f.write("id,lab_name,pc_number,ip_address,mac_address,status\n")
        for row in rows:
            f.write(f"{row['id']},\"{row['lab_name']}\",{row['pc_number']},{row['ip_address']},{row['mac_address']},{row['status']}\n")

    print(f"[+] Exported {len(rows)} monitor endpoints to '{TXT_EXPORT_FILE}' and '{CSV_EXPORT_FILE}'.")


def verify_database(conn: sqlite3.Connection):
    """Print an inspection summary of the populated tables."""
    cursor = conn.cursor()

    print("\n" + "=" * 80)
    print("                      DATABASE VERIFICATION SUMMARY")
    print("=" * 80)

    # Labs
    cursor.execute("SELECT id, lab_name, location, total_pcs FROM LABS")
    labs = cursor.fetchall()
    print(f"\n[LABS TABLE - {len(labs)} entries]")
    for lab in labs:
        print(f"  ID: {lab['id']} | {lab['lab_name']} | {lab['location']} | Total PCs: {lab['total_pcs']}")

    # Total Computers
    cursor.execute("SELECT COUNT(*) AS cnt FROM COMPUTERS")
    total_pcs = cursor.fetchone()["cnt"]

    # PC-30 check specifically
    cursor.execute(
        """
        SELECT c.id, l.lab_name, c.pc_number, c.ip_address, c.mac_address, c.status
        FROM COMPUTERS c
        JOIN LABS l ON c.lab_id = l.id
        WHERE c.pc_number = 'PC-30'
        """
    )
    pc30_list = cursor.fetchall()
    print(f"\n[COMPUTERS TABLE - Total {total_pcs} PCs]")
    print("  Highlighting PC-30 entries (Targeted for C monitoring):")
    for pc in pc30_list:
        print(f"  -> ID: {pc['id']} | {pc['lab_name']} | {pc['pc_number']} | IP: {pc['ip_address']} | MAC: {pc['mac_address']} | Status: {pc['status']}")

    # Users
    cursor.execute("SELECT id, username, full_name, email, role FROM USERS")
    users = cursor.fetchall()
    print(f"\n[USERS TABLE - {len(users)} entries]")
    for user in users:
        print(f"  ID: {user['id']} | @{user['username']:<14} | {user['full_name']:<25} | Role: {user['role']:<10} | Email: {user['email']}")

    # Tickets
    cursor.execute(
        """
        SELECT t.id, t.ticket_number, u.username AS reporter, l.lab_name, c.pc_number,
               c.ip_address, t.issue_category, t.status, t.priority, t.reported_at
        FROM TICKETS t
        JOIN USERS u ON t.user_id = u.id
        JOIN LABS l ON t.lab_id = l.id
        JOIN COMPUTERS c ON t.computer_id = c.id
        ORDER BY t.id
        """
    )
    tickets = cursor.fetchall()
    print(f"\n[TICKETS TABLE - {len(tickets)} entries]")
    for t in tickets:
        print(f"  #{t['id']} [{t['ticket_number']}] Status: {t['status']:<10} | Priority: {t['priority']:<6} | Lab: {t['lab_name'][:12]} | {t['pc_number']} ({t['ip_address']})")
        print(f"      Category: {t['issue_category']} | Reported By: @{t['reporter']} at {t['reported_at']}")

    print("=" * 80 + "\n")


def main():
    """Main execution flow for setting up the Data Tier."""
    print("=" * 80)
    print("   COLLEGE LAB PC FAULT REPORTING SYSTEM - DATA TIER SETUP (STEP 1)")
    print("=" * 80)

    # Handle --reset argument if user wants a clean slate
    if "--reset" in sys.argv and os.path.exists(DB_FILE):
        print(f"[*] Removing existing database file: {DB_FILE}")
        os.remove(DB_FILE)

    conn = get_db_connection()

    try:
        initialize_schema(conn)
        populate_labs(conn)
        populate_computers(conn)
        populate_users(conn)
        populate_tickets(conn)
        export_for_c_program(conn)
        verify_database(conn)
        print("[SUCCESS] Step 1 Data Tier setup completed successfully!")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
