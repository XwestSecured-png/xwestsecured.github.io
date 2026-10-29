#!/usr/bin/env python3
"""
Builds a synthetic security-operations SQLite database for threat-hunting practice.

Tables
  employees(employee_id, device_id, username, department, office)
  machines(device_id, operating_system, os_patch_date, email_client)
  log_in_attempts(event_id, username, login_date, login_time, country, ip_address, success)
  web_requests(request_id, ts, src_ip, method, uri, status, bytes, user_agent)

Seeded with normal activity plus planted suspicious events so every hunt query
in hunting/threat_hunting_queries.sql returns something meaningful.
Deterministic (fixed random seed) so results are reproducible.

    python3 lab/build_lab_db.py --db lab/soc_lab.db
"""
import argparse
import random
import sqlite3
from datetime import date, datetime, time, timedelta

random.seed(2026)

DEPTS = ["Finance", "HR", "IT", "Sales", "Marketing", "Operations"]
OFFICES = ["East-170", "West-210", "North-110", "South-150", "Central-100"]
OSES = [("Windows 11 24H2", "2026-10-14"), ("Windows 11 23H2", "2026-09-09"),
        ("Windows 10 22H2", "2025-10-14"), ("macOS 15", "2026-10-01"),
        ("Ubuntu 24.04 LTS", "2026-10-20")]
FIRST = ["alex", "blake", "casey", "drew", "emery", "finley", "gray", "harper", "indy",
         "jordan", "kai", "logan", "morgan", "noel", "oak", "parker", "quinn", "reese",
         "sage", "taylor", "uri", "val", "wren", "xen", "yael", "zion"]


def build(path: str) -> None:
    con = sqlite3.connect(path)
    con.executescript("""
    DROP TABLE IF EXISTS employees; DROP TABLE IF EXISTS machines;
    DROP TABLE IF EXISTS log_in_attempts; DROP TABLE IF EXISTS web_requests;
    CREATE TABLE machines(device_id TEXT PRIMARY KEY, operating_system TEXT,
                          os_patch_date DATE, email_client TEXT);
    CREATE TABLE employees(employee_id INTEGER PRIMARY KEY, device_id TEXT REFERENCES machines,
                           username TEXT UNIQUE, department TEXT, office TEXT);
    CREATE TABLE log_in_attempts(event_id INTEGER PRIMARY KEY, username TEXT, login_date DATE,
                                 login_time TIME, country TEXT, ip_address TEXT, success INTEGER);
    CREATE TABLE web_requests(request_id INTEGER PRIMARY KEY, ts DATETIME, src_ip TEXT, method TEXT,
                              uri TEXT, status INTEGER, bytes INTEGER, user_agent TEXT);
    """)

    users = []
    for i, f in enumerate(FIRST * 3):
        uname = f"{f}{i:02d}"
        dev = f"d{1000 + i:04d}"
        os_name, patch = random.choice(OSES)
        con.execute("INSERT INTO machines VALUES (?,?,?,?)",
                    (dev, os_name, patch, random.choice(["Outlook", "Thunderbird", "Mail"])))
        con.execute("INSERT INTO employees VALUES (?,?,?,?,?)",
                    (1000 + i, dev, uname, random.choice(DEPTS), random.choice(OFFICES)))
        users.append(uname)

    # Normal logins: business hours, US, mostly success
    eid = 1
    start = date(2026, 10, 19)
    for d in range(7):
        day = start + timedelta(days=d)
        for _ in range(120):
            t = time(random.randint(7, 17), random.randint(0, 59), random.randint(0, 59))
            con.execute("INSERT INTO log_in_attempts VALUES (?,?,?,?,?,?,?)",
                        (eid, random.choice(users), day.isoformat(), t.isoformat(), "USA",
                         f"10.20.{random.randint(1, 9)}.{random.randint(2, 250)}",
                         0 if random.random() < 0.04 else 1))
            eid += 1

    def add_login(u, day, hh, mm, country, ip, ok):
        nonlocal eid
        con.execute("INSERT INTO log_in_attempts VALUES (?,?,?,?,?,?,?)",
                    (eid, u, day, f"{hh:02d}:{mm:02d}:00", country, ip, ok))
        eid += 1

    # Planted: after-hours failures, impossible travel, brute force, spray
    victim = users[5]
    add_login(victim, "2026-10-23", 9, 5, "USA", "10.20.3.44", 1)
    add_login(victim, "2026-10-23", 9, 47, "NLD", "203.0.113.60", 1)          # impossible travel
    for m in range(12):
        add_login(users[9], "2026-10-24", 23, m, "USA", "198.51.100.9", 0)    # brute force after hours
    for k, u in enumerate(users[20:28]):
        add_login(u, "2026-10-25", 2, k, "RUS", "198.51.100.77", 0)           # spray
    add_login(users[22], "2026-10-25", 2, 15, "RUS", "198.51.100.77", 1)      # spray success

    # Web requests: normal + SQLi + scanner
    rid = 1
    base = datetime(2026, 10, 24, 8, 0, 0)
    pages = ["/", "/products", "/products?id=12", "/cart", "/login", "/static/app.js", "/search?q=shoes"]
    for i in range(400):
        con.execute("INSERT INTO web_requests VALUES (?,?,?,?,?,?,?,?)",
                    (rid, (base + timedelta(seconds=i * 90)).isoformat(sep=" "),
                     f"192.0.2.{random.randint(2, 200)}", "GET", random.choice(pages), 200,
                     random.randint(800, 40000), "Mozilla/5.0"))
        rid += 1
    attacks = [
        "/products?id=12' OR '1'='1", "/products?id=12 UNION SELECT username,password FROM users--",
        "/products?id=12;WAITFOR DELAY '0:0:5'--", "/search?q=%27%20OR%201%3D1--",
        "/products?id=1 AND SLEEP(5)", "/login?user=admin'--",
        "/products?id=12 AND 1=CONVERT(int,(SELECT @@version))",
    ]
    t = datetime(2026, 10, 24, 14, 2, 0)
    for i, a in enumerate(attacks * 3):
        con.execute("INSERT INTO web_requests VALUES (?,?,?,?,?,?,?,?)",
                    (rid, (t + timedelta(seconds=i * 4)).isoformat(sep=" "), "203.0.113.99", "GET", a,
                     500 if i % 3 == 0 else 200, random.randint(200, 90000), "sqlmap/1.8"))
        rid += 1
    con.commit()
    con.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="lab/soc_lab.db")
    build(ap.parse_args().db)
    print("[+] lab database built")
