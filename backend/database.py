import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "ddos_events.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            ip          TEXT NOT NULL,
            country     TEXT,
            city        TEXT,
            latitude    REAL,
            longitude   REAL,
            asn         INTEGER,
            asn_org     TEXT,
            url         TEXT,
            method      TEXT,
            user_agent  TEXT,
            abuse_score INTEGER DEFAULT 0,
            ddos_confidence REAL DEFAULT 0.0,
            flagged     INTEGER DEFAULT 0
        )
    """)

    cursor.execute(""" CREATE TABLE IF NOT EXISTS ip_cache (
                   ip          TEXT PRIMARY KEY,
                   abuse_score INTEGER,
                   checked_at  TEXT NOT NULL
    )""")

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_ip
        ON events(ip)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_timestamp
        ON events(timestamp)
    """)

    conn.commit()
    conn.close()
    print(f"Database initialised at {DB_PATH}")

def insert_event(data: dict) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO events (
            timestamp, ip, country, city,
            latitude, longitude, asn, asn_org,
            url, method, user_agent,
            abuse_score, ddos_confidence, flagged
        ) VALUES (
            :timestamp, :ip, :country, :city,
            :latitude, :longitude, :asn, :asn_org,
            :url, :method, :user_agent,
            :abuse_score, :ddos_confidence, :flagged
        )
    """, data)
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id

def get_cached_abuse_score(ip: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT abuse_score FROM ip_cache
        WHERE ip = ?
        AND checked_at > datetime('now', '-24 hours')
    """, (ip,))
    row = cursor.fetchone()
    conn.close()
    return row["abuse_score"] if row else None

def cache_abuse_score(ip: str, score: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO ip_cache (ip, abuse_score, checked_at)
        VALUES (?, ?, datetime('now'))
        ON CONFLICT(ip) DO UPDATE SET
            abuse_score = excluded.abuse_score,
            checked_at  = excluded.checked_at
    """, (ip, score))
    conn.commit()
    conn.close()

def get_recent_events(limit: int = 100):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM events
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]