from database import get_connection
import pandas as pd


def fetch_realtime_data():
    """Fetch real-time labeled data for retraining."""
    conn = get_connection()
    query = """
        SELECT nf.duration, nf.protocol_type, nf.service, nf.flag,
               nf.src_bytes, nf.dst_bytes,
               p.attack_type
        FROM network_flows nf
        JOIN predictions p ON nf.flow_id = p.flow_id
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df


def should_retrain():
    # FIX: open and close connection per call — don't rely on module-level conn
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM alerts_logs")
    count = cursor.fetchone()[0]
    conn.close()
    return count >= 200


def reset_alert_count():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerts_logs")
    conn.commit()
    conn.close()
