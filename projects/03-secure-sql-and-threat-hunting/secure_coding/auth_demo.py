#!/usr/bin/env python3
"""
SQL Injection: Vulnerable vs. Secure Implementation
===================================================

Side-by-side demonstration of OWASP Top 10:2025 **A05 Injection** (CWE-89) and
**A07 Authentication Failures**, using an in-memory SQLite database so it is
completely self-contained and safe to run anywhere.

    python3 auth_demo.py          # runs the attack demo against both versions

The "vulnerable" class exists ONLY for education and is never imported by
anything else. Do not reuse it.

Secure controls demonstrated
  1. Parameterized queries (prepared statements). Data never becomes code.
  2. Allow-list validation for identifiers that cannot be parameterized
     (ORDER BY column, sort direction).
  3. Strong password storage: scrypt (memory-hard KDF) with per-user random salt,
     constant-time comparison (OWASP Password Storage Cheat Sheet).
  4. Generic error messages. No user enumeration, no SQL errors leaked.
  5. Input length limits and type checks (defense in depth, NOT the primary control).
  6. Least-privilege connection: read-only for lookups (SQLite `mode=ro` stands in
     for a SELECT-only DB role in PostgreSQL/MySQL/SQL Server).

Author: Xiome West | License: MIT
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import tempfile

# --------------------------------------------------------------------------- #
# Password hashing (scrypt, stdlib)
# --------------------------------------------------------------------------- #
# OWASP-recommended scrypt baseline: N=2^17, r=8, p=1 (~128 MiB). Tune for your hardware.
SCRYPT_N, SCRYPT_R, SCRYPT_P, DKLEN = 2**17, 8, 1, 64
SCRYPT_MAXMEM = 256 * 1024 * 1024


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                        dklen=DKLEN, maxmem=SCRYPT_MAXMEM)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt_hex, dk_hex = stored.split("$")
        dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=int(n), r=int(r),
                            p=int(p), dklen=len(dk_hex) // 2, maxmem=SCRYPT_MAXMEM)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except (ValueError, TypeError):
        return False


# A dummy hash so failed lookups take the same time as real ones (anti-enumeration).
_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


# --------------------------------------------------------------------------- #
# Lab database
# --------------------------------------------------------------------------- #

def build_db(path: str) -> None:
    con = sqlite3.connect(path)
    con.executescript("""
        DROP TABLE IF EXISTS users;
        CREATE TABLE users (
            id            INTEGER PRIMARY KEY,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,     -- secure app
            password_pt   TEXT NOT NULL,     -- vulnerable app (plaintext, anti-pattern!)
            role          TEXT NOT NULL,
            department    TEXT NOT NULL
        );
    """)
    seed = [("admin", "Correct-Horse-Battery-Staple-42", "admin", "IT"),
            ("jdoe", "spring-meadow-lantern-77", "user", "Finance"),
            ("asmith", "quiet-river-copper-19", "user", "HR"),
            ("mlee", "amber-forest-signal-08", "user", "IT")]
    con.executemany(
        "INSERT INTO users (username, password_hash, password_pt, role, department) VALUES (?,?,?,?,?)",
        [(u, hash_password(p), p, r, d) for u, p, r, d in seed])
    con.commit()
    con.close()


# --------------------------------------------------------------------------- #
# ❌ VULNERABLE (educational only)
# --------------------------------------------------------------------------- #

class VulnerableAuth:
    def __init__(self, path: str):
        self.con = sqlite3.connect(path)

    def login(self, username: str, password: str):
        # String concatenation turns attacker data into SQL code.
        q = (f"SELECT username, role FROM users "
             f"WHERE username = '{username}' AND password_pt = '{password}'")
        try:
            return self.con.execute(q).fetchone()
        except sqlite3.Error as e:
            return f"DB ERROR LEAKED TO USER: {e}"      # info disclosure, too

    def search(self, dept: str, sort: str):
        q = f"SELECT username, department FROM users WHERE department = '{dept}' ORDER BY {sort}"
        try:
            return self.con.execute(q).fetchall()
        except sqlite3.Error as e:
            return f"DB ERROR LEAKED TO USER: {e}"


# --------------------------------------------------------------------------- #
# ✅ SECURE
# --------------------------------------------------------------------------- #

class SecureAuth:
    MAX_USER, MAX_PASS = 64, 128
    SORTABLE = {"username", "department"}           # allow-list for identifiers
    DIRECTIONS = {"asc": "ASC", "desc": "DESC"}

    def __init__(self, path: str):
        # Least privilege: this connection cannot write (read-only URI).
        self.con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)

    def login(self, username: str, password: str) -> tuple | None:
        if not isinstance(username, str) or not isinstance(password, str):
            return None
        if not (0 < len(username) <= self.MAX_USER and 0 < len(password) <= self.MAX_PASS):
            return None
        row = self.con.execute(
            "SELECT username, role, password_hash FROM users WHERE username = ?",  # parameterized
            (username,),
        ).fetchone()
        stored = row[2] if row else _DUMMY_HASH        # constant work whether user exists or not
        if verify_password(password, stored) and row:
            return (row[0], row[1])
        return None                                     # generic failure, caller says "invalid credentials"

    def search(self, dept: str, sort: str = "username", direction: str = "asc") -> list:
        col = sort if sort in self.SORTABLE else "username"
        dirn = self.DIRECTIONS.get(direction.lower(), "ASC")
        return self.con.execute(
            f"SELECT username, department FROM users WHERE department = ? ORDER BY {col} {dirn}",  # nosec - allow-listed identifiers
            (dept,),
        ).fetchall()


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #

def _blind(guess: str) -> str:
    cond = f"(SELECT substr(password_pt,1,1) FROM users WHERE username='admin')='{guess}'"
    return f"CASE WHEN {cond} THEN id ELSE -id END"


ATTACKS = [
    ("Auth bypass (tautology)",       "login",  ("admin' --", "anything")),
    ("Auth bypass (OR 1=1)",          "login",  ("x' OR '1'='1", "x' OR '1'='1")),
    ("UNION data exfiltration",       "search", ("x' UNION SELECT username, password_pt FROM users --", "username")),
    # Blind boolean injection via ORDER BY: row order leaks one bit per request.
    ("ORDER BY blind: is admin pw[1]=='C'?", "search", ("IT", _blind("C"))),
    ("ORDER BY blind: is admin pw[1]=='X'?", "search", ("IT", _blind("X"))),
    ("Error-based probing",           "login",  ("admin'", "x")),
]


def main() -> None:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        build_db(path)
        vuln, safe = VulnerableAuth(path), SecureAuth(path)
        print("=" * 78)
        print(" SQL Injection demo: OWASP Top 10:2025 A05 Injection | CWE-89 | ATT&CK T1190")
        print("=" * 78)
        for name, op, args in ATTACKS:
            print(f"\n▶ {name}\n  payload: {args}")
            v = getattr(vuln, op)(*args)
            s = getattr(safe, op)(*args)
            print(f"  ❌ vulnerable -> {v}")
            if "blind" in name:
                print("     (admin listed first = guess correct; attacker repeats per character)")
            print(f"  ✅ secure     -> {s if s else 'rejected: invalid credentials / no rows'}")
        print("\n▶ Legitimate login still works on the secure version:")
        print(f"  ✅ secure     -> {safe.login('jdoe', 'spring-meadow-lantern-77')}")
        print("\n▶ Write attempt through the read-only (least-privilege) connection:")
        try:
            safe.con.execute("DELETE FROM users")
            print("  ❌ write succeeded")
        except sqlite3.OperationalError as e:
            print(f"  ✅ blocked: {e}")
    finally:
        os.remove(path)


if __name__ == "__main__":
    main()
