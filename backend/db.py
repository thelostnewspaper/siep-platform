import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "siep.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create devices table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        device_id TEXT PRIMARY KEY,
        cert_pem TEXT,
        registered_at TEXT,
        status TEXT,
        trust_score INTEGER DEFAULT 100,
        firmware_version TEXT,
        ip_address TEXT,
        gateway_node TEXT,
        device_type TEXT,
        last_seen TEXT
    )
    """)
    
    # Create audit_logs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        level TEXT,
        device_id TEXT,
        gateway TEXT,
        message TEXT,
        payload TEXT,
        action_taken TEXT
    )
    """)
    
    # Create policies table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS policies (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    """)
    
    # Create nis2_checklist table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS nis2_checklist (
        id TEXT PRIMARY KEY,
        category TEXT,
        requirement TEXT,
        status TEXT,
        notes TEXT
    )
    """)
    
    # Insert default policies if they don't exist
    default_policies = [
        ("ddos_threshold_per_min", "120"),
        ("auto_quarantine", "true"),
        ("trust_quarantine_threshold", "70"),
        ("trust_block_threshold", "45"),
        ("mesh_intel_sync", "true")
    ]
    for key, val in default_policies:
        cursor.execute("INSERT OR IGNORE INTO policies (key, value) VALUES (?, ?)", (key, val))
        
    # Insert default NIS2 Checklist requirements if empty
    cursor.execute("SELECT COUNT(*) FROM nis2_checklist")
    if cursor.fetchone()[0] == 0:
        nis2_requirements = [
            ("NIS2-01", "Asset Inventory", "Maintain an up-to-date registry of all active operational technology (OT) assets and edge devices.", "Compliant", "Auto-updated via device registration registry."),
            ("NIS2-02", "Access Control & PKI", "Ensure strong endpoint authentication through certificate-based validation (TLS client certificates).", "Compliant", "All simulated devices must utilize Root CA certs to register."),
            ("NIS2-03", "Audit Logging & Traceability", "Store comprehensive security audit logs and events for threat detection and digital forensics.", "Compliant", "All message processing triggers persistent audit logging."),
            ("NIS2-04", "Incident Reporting & Response", "Establish automatic incident handling and mitigation rules for immediate threat response.", "In-Progress", "Need to execute auto-mitigation algorithms using Autonomous Agent."),
            ("NIS2-05", "Risk Score Engine", "Provide dynamic risk evaluation for operational devices to prioritize incidents.", "In-Progress", "Trust scoring engine actively evaluates packet payload anomalies."),
            ("NIS2-06", "Supply Chain Security", "Verify firmware integrity, versioning, and vendor certificates of connected industrial IoT hardware.", "Non-Compliant", "Simulator has some nodes running legacy/outdated firmware versions.")
        ]
        for req_id, cat, req, status, notes in nis2_requirements:
            cursor.execute("INSERT INTO nis2_checklist (id, category, requirement, status, notes) VALUES (?, ?, ?, ?, ?)",
                           (req_id, cat, req, status, notes))
            
    conn.commit()
    conn.close()

# Initialize DB on load
init_db()

# Device Helper Functions
def register_device(device_id: str, cert_pem: str, firmware: str, ip: str, gateway: str, device_type: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    cursor.execute("""
    INSERT OR REPLACE INTO devices (device_id, cert_pem, registered_at, status, trust_score, firmware_version, ip_address, gateway_node, device_type, last_seen)
    VALUES (?, ?, ?, ?, 100, ?, ?, ?, ?, ?)
    """, (device_id, cert_pem, now, "online", firmware, ip, gateway, device_type, now))
    conn.commit()
    conn.close()

def get_devices():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices")
    devices = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return devices

def get_device(device_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def update_device_status(device_id: str, status: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE devices SET status = ?, last_seen = ? WHERE device_id = ?", (status, datetime.now().isoformat(), device_id))
    conn.commit()
    conn.close()

def update_device_trust(device_id: str, trust_score: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE devices SET trust_score = ?, last_seen = ? WHERE device_id = ?", (trust_score, datetime.now().isoformat(), device_id))
    conn.commit()
    conn.close()

def delete_device(device_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
    conn.commit()
    conn.close()

# Logs Functions
def add_audit_log(level: str, device_id: str, gateway: str, message: str, payload: str = "", action_taken: str = ""):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    cursor.execute("""
    INSERT INTO audit_logs (timestamp, level, device_id, gateway, message, payload, action_taken)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (now, level, device_id, gateway, message, payload, action_taken))
    conn.commit()
    conn.close()

def get_audit_logs(limit: int = 100):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return logs

# Policy Functions
def get_policies():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM policies")
    policies = {row["key"]: row["value"] for row in cursor.fetchall()}
    conn.close()
    return policies

def update_policy(key: str, value: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO policies (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

# NIS2 Checklist Functions
def get_nis2_checklist():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM nis2_checklist")
    items = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return items

def update_nis2_item(item_id: str, status: str, notes: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE nis2_checklist SET status = ?, notes = ? WHERE id = ?", (status, notes, item_id))
    conn.commit()
    conn.close()
