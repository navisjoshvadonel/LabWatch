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
    lab_name TEXT UNIQUE NOT NULL,
    department TEXT NOT NULL,
    location TEXT NOT NULL,
    total_pcs INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. COMPUTERS TABLE
-- Stores inventory, network identifiers (IP & MAC for C pinger / UDP heartbeat), and status
CREATE TABLE IF NOT EXISTS COMPUTERS (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lab_id INTEGER NOT NULL,
    pc_number TEXT NOT NULL,
    ip_address TEXT UNIQUE NOT NULL,
    mac_address TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL DEFAULT 'Online',
    specs TEXT,
    last_heartbeat TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (lab_id) REFERENCES LABS (id) ON DELETE CASCADE,
    UNIQUE (lab_id, pc_number)
);

-- 3. USERS TABLE
-- Stores portal users: Students, Staff, Lab Technicians, and System Administrators
CREATE TABLE IF NOT EXISTS USERS (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('student', 'staff', 'technician', 'admin')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 4. TICKETS TABLE
-- Stores fault reports submitted by users and managed by technicians
CREATE TABLE IF NOT EXISTS TICKETS (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_number TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    lab_id INTEGER NOT NULL,
    computer_id INTEGER NOT NULL,
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
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending' CHECK(
        status IN ('Pending', 'In Progress', 'Resolved', 'Closed')
    ),
    priority TEXT NOT NULL DEFAULT 'Medium' CHECK(
        priority IN ('Low', 'Medium', 'High', 'Critical')
    ),
    reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    technician_id INTEGER,
    resolution_notes TEXT,
    FOREIGN KEY (user_id) REFERENCES USERS (id) ON DELETE RESTRICT,
    FOREIGN KEY (lab_id) REFERENCES LABS (id) ON DELETE RESTRICT,
    FOREIGN KEY (computer_id) REFERENCES COMPUTERS (id) ON DELETE RESTRICT,
    FOREIGN KEY (technician_id) REFERENCES USERS (id) ON DELETE SET NULL
);

-- Indices for performance
CREATE INDEX IF NOT EXISTS idx_computers_lab_id ON COMPUTERS(lab_id);
CREATE INDEX IF NOT EXISTS idx_computers_ip ON COMPUTERS(ip_address);
CREATE INDEX IF NOT EXISTS idx_computers_status ON COMPUTERS(status);
CREATE INDEX IF NOT EXISTS idx_tickets_status ON TICKETS(status);
CREATE INDEX IF NOT EXISTS idx_tickets_computer_id ON TICKETS(computer_id);
CREATE INDEX IF NOT EXISTS idx_tickets_user_id ON TICKETS(user_id);
CREATE INDEX IF NOT EXISTS idx_tickets_lab_id ON TICKETS(lab_id);
