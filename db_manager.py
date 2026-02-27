import sqlite3

DB_NAME = "threats.db"


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        attack_type TEXT,
        event_count INTEGER,
        severity TEXT,
        mitre TEXT,
        time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()


def insert_alert(ip, attack_type, event_count, severity, mitre):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts (ip, attack_type, event_count, severity, mitre)
        VALUES (?, ?, ?, ?, ?)
    """, (ip, attack_type, event_count, severity, mitre))

    conn.commit()
    conn.close()


def get_all_alerts():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT ip, attack_type, event_count, severity, mitre, time
        FROM alerts
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    alerts = []
    for row in rows:
        alerts.append({
            "ip": row[0],
            "attack_type": row[1],
            "event_count": row[2],
            "severity": row[3],
            "mitre": row[4],
            "time": row[5]
        })

    return alerts

def clear_alerts():
    conn = sqlite3.connect("threats.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()