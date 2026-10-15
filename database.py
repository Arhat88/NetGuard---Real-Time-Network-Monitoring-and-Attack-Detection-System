import sqlite3
import time

DB_PATH = "ids.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def safe_execute(query, params=()):
    """Opens its own connection, executes, commits, and closes. Returns lastrowid."""
    conn = get_connection()
    cursor = conn.cursor()
    for _ in range(5):
        try:
            cursor.execute(query, params)
            conn.commit()
            lastrowid = cursor.lastrowid
            conn.close()
            return lastrowid          # <-- returns real lastrowid
        except sqlite3.OperationalError as e:
            if "locked" in str(e):
                time.sleep(0.2)
            else:
                conn.close()
                raise e
    conn.close()
    return None


def create_table():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""CREATE TABLE IF NOT EXISTS users(
                   user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                   username TEXT UNIQUE,
                   password TEXT,
                   email TEXT,
                   last_login DATETIME)""")

    cursor.execute("""CREATE TABLE IF NOT EXISTS network_flows(
                   flow_id INTEGER PRIMARY KEY AUTOINCREMENT,
                   timestamp DATETIME DEFAULT (datetime('now', 'localtime')),
                   src_ip TEXT,
                   dst_ip TEXT,
                   src_port INTEGER,
                   dst_port INTEGER,
                   protocol_type TEXT,
                   service TEXT,
                   flag TEXT,
                   duration REAL,
                   src_bytes INTEGER,
                   dst_bytes INTEGER,
                   packet_count INTEGER,
                   count INTEGER,
                   src_count INTEGER,
                   srv_count INTEGER,
                   same_srv_rate REAL,
                   diff_srv_rate REAL,
                   src_diff_srv_rate REAL,
                   dst_host_count INTEGER,
                   dst_host_srv_count INTEGER,
                   dst_host_diff_srv_rate REAL,
                   dst_host_same_srv_rate REAL,
                   serror_rate REAL,
                   srv_serror_rate REAL,
                   dst_host_serror_rate REAL,
                   user_id INTEGER)""")

    cursor.execute("""CREATE TABLE IF NOT EXISTS predictions(
                prediction_id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id INTEGER,
                prediction_label TEXT,
                attack_type TEXT,
                confidence_score REAL,
                FOREIGN KEY(flow_id) REFERENCES network_flows(flow_id) ON DELETE CASCADE)""")

    cursor.execute("""CREATE TABLE IF NOT EXISTS alerts_logs(
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id INTEGER,
                timestamp DATETIME DEFAULT (datetime('now', 'localtime')),
                alert_type TEXT,
                severity_level TEXT,
                status TEXT,
                message TEXT,
                handled_by INTEGER,
                FOREIGN KEY(flow_id) REFERENCES network_flows(flow_id) ON DELETE CASCADE,
                FOREIGN KEY(handled_by) REFERENCES users(user_id))""")

    conn.commit()
    conn.close()
