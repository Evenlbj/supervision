import sqlite3
import os
import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "supervision.db")


# ================= CONNEXION =================
def get_db():
    return sqlite3.connect(DB)


# ================= INIT =================
def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS machines(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        hostname TEXT,
        status TEXT,
        last_seen TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS ports(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        machine_id INTEGER,
        port INTEGER,
        state TEXT,
        service TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        machine_id INTEGER,
        cve TEXT,
        cvss REAL,
        severity TEXT
    )
    """)

    conn.commit()
    conn.close()


# ================= ADD MACHINE =================
def add_machine(ip, hostname, status):
    conn = get_db()
    c = conn.cursor()

    c.execute("""
    INSERT INTO machines(ip, hostname, status, last_seen)
    VALUES (?, ?, ?, ?)
    """, (ip, hostname, status, str(datetime.datetime.now())))

    conn.commit()
    machine_id = c.lastrowid
    conn.close()

    return machine_id


# ================= ADD PORT =================
def add_port(machine_id, port, state, service):
    conn = get_db()
    c = conn.cursor()

    c.execute("""
    INSERT INTO ports(machine_id, port, state, service)
    VALUES (?, ?, ?, ?)
    """, (machine_id, port, state, service))

    conn.commit()
    conn.close()


# ================= ADD VULN =================
def add_vuln(machine_id, cve, cvss, severity):
    conn = get_db()
    c = conn.cursor()

    c.execute("""
    INSERT INTO vulnerabilities(machine_id, cve, cvss, severity)
    VALUES (?, ?, ?, ?)
    """, (machine_id, cve, cvss, severity))

    conn.commit()
    conn.close()
