-- VulnSight SQLite — reference DDL (matches what the app creates at runtime).
-- Path: set VULNSIGHT_DB_PATH (default database/vulnsight.db).
-- You do not need to run this file for normal use; AlertRepository + AuthRepository
-- create these tables on startup. Use this for docs, reviews, or manual tooling.

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    severity TEXT NOT NULL,
    is_malicious INTEGER NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_dst_ip ON alerts(destination_ip);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);

-- Optional teammate-compatible flow tables
CREATE TABLE IF NOT EXISTS pcap_file (
    id TEXT PRIMARY KEY,
    filename TEXT,
    filepath TEXT,
    file_size INTEGER,
    uploaded_at TEXT,
    source TEXT
);

CREATE TABLE IF NOT EXISTS packet (
    id TEXT PRIMARY KEY,
    timestamp TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    packet_length INTEGER,
    tcp_flags TEXT,
    pcap_id TEXT,
    session_id TEXT
);

CREATE TABLE IF NOT EXISTS flow (
    id TEXT PRIMARY KEY,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    start_time TEXT,
    end_time TEXT,
    pcap_id TEXT,
    total_packets INTEGER,
    total_bytes INTEGER,
    duration REAL,
    packet_per_sec REAL,
    bytes_per_sec REAL,
    avg_packet_size REAL
);

CREATE INDEX IF NOT EXISTS idx_flow_start_time ON flow(start_time);
