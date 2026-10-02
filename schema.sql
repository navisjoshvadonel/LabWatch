-- ============================================================================
-- College Lab PC Fault Reporting System (LabPulse)
-- Database Schema: Data Tier Definition
-- Tables: LABS, COMPUTERS, USERS, TICKETS
-- ============================================================================

PRAGMA foreign_keys = ON;

-- 1. LABS TABLE
-- Stores information about physical computer laboratories in the institution
CREATE TABLE IF NOT EXISTS LABS (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lab_name TEXT UNIQUE NOT NULL,             -- e.g., 'Lab A - Network Lab', 'Lab B - Systems Lab'
    department TEXT NOT NULL,                  -- e.g., 'Computer Science & Engineering'
    location TEXT NOT NULL,                    -- e.g., 'Building 2, 3rd Floor, Room 301'
    total_pcs INTEGER NOT NULL DEFAULT 0,      -- Number of configured workstations
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. COMPUTERS TABLE
-- Stores inventory, network identifiers (IP & MAC for C pinger / UDP heartbeat), and status
CREATE TABLE IF NOT EXISTS COMPUTERS (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lab_id INTEGER NOT NULL,
    pc_number TEXT NOT NULL,                   -- e.g., 'PC-01', 'PC-30'
    ip_address TEXT UNIQUE NOT NULL,           -- e.g., '192.168.1.130'
    mac_address TEXT UNIQUE NOT NULL,          -- e.g., '00:1A:2B:3C:4D:1E'
    status TEXT NOT NULL DEFAULT 'Online',     -- 'Online', 'Offline', 'Faulty', 'Maintenance'
    specs TEXT,                                -- Hardware specs e.g. 'Core i5-12400, 16GB RAM, 512GB SSD'
    last_heartbeat TIMESTAMP,                  -- Last UDP/ICMP heartbeat received by monitor
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (lab_id) REFERENCES LABS (id) ON DELETE CASCADE,
    UNIQUE (lab_id, pc_number)
);

-- 3. USERS TABLE
-- Stores portal users: Students, Staff, Lab Technicians, and System Administrators
CREATE TABLE IF NOT EXISTS USERS (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,             -- e.g., 'student1', 'tech_john', 'admin'
    password_hash TEXT NOT NULL,               -- Hashed password for authentication
    full_name TEXT NOT NULL,                   -- e.g., 'Alice Smith'
    email TEXT UNIQUE NOT NULL,                -- For SMTP ticket notifications
    role TEXT NOT NULL CHECK(role IN ('student', 'staff', 'technician', 'admin')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 4. TICKETS TABLE
-- Stores fault reports submitted by users and managed by technicians
CREATE TABLE IF NOT EXISTS TICKETS (
    id INTEGER PRIMARY KEY AUTOINCREMENT,      -- Unique Ticket ID (e.g. 101, 102)
    ticket_number TEXT UNIQUE NOT NULL,        -- Human-readable format (e.g., 'TCK-101')
    user_id INTEGER NOT NULL,                  -- Reporter ID
    lab_id INTEGER NOT NULL,                   -- Lab where fault occurred
    computer_id INTEGER NOT NULL,              -- Target computer ID
    issue_category TEXT NOT NULL CHECK(
        issue_category IN (
            'Network Connectivity',
            'Operating System',
            'Hardware Fault',
            'Peripheral / Display',
            'Software Crash',
            'Power Issue',
            'Other'
        )
    ),
    description TEXT NOT NULL,                 -- Detailed fault description from user
    status TEXT NOT NULL DEFAULT 'Pending' CHECK(
        status IN ('Pending', 'In Progress', 'Resolved', 'Closed')
    ),
    priority TEXT NOT NULL DEFAULT 'Medium' CHECK(
        priority IN ('Low', 'Medium', 'High', 'Critical')
    ),
    reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,                     -- Timestamp when technician resolves ticket
    technician_id INTEGER,                     -- Technician who resolved the ticket
    resolution_notes TEXT,                     -- Notes recorded upon resolution
    FOREIGN KEY (user_id) REFERENCES USERS (id) ON DELETE RESTRICT,
    FOREIGN KEY (lab_id) REFERENCES LABS (id) ON DELETE RESTRICT,
    FOREIGN KEY (computer_id) REFERENCES COMPUTERS (id) ON DELETE RESTRICT,
    FOREIGN KEY (technician_id) REFERENCES USERS (id) ON DELETE SET NULL
);

-- Indices for performance (Query optimization for technicians and dashboard views)
CREATE INDEX IF NOT EXISTS idx_computers_lab_id ON COMPUTERS(lab_id);
CREATE INDEX IF NOT EXISTS idx_computers_ip ON COMPUTERS(ip_address);
CREATE INDEX IF NOT EXISTS idx_computers_status ON COMPUTERS(status);
CREATE INDEX IF NOT EXISTS idx_tickets_status ON TICKETS(status);
CREATE INDEX IF NOT EXISTS idx_tickets_computer_id ON TICKETS(computer_id);
CREATE INDEX IF NOT EXISTS idx_tickets_user_id ON TICKETS(user_id);
CREATE INDEX IF NOT EXISTS idx_tickets_lab_id ON TICKETS(lab_id);
