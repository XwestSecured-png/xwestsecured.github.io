#!/usr/bin/env python3
"""
Deterministically generates synthetic Zeek conn.log and dns.log files containing
normal traffic plus planted attack scenarios. All external IPs come from the
RFC 5737 documentation ranges, and domains use the reserved .example TLD.

    python3 sample_data/generate_samples.py
"""
import base64
import random
from pathlib import Path

random.seed(42)
OUT = Path(__file__).resolve().parent
T0 = 1793174400.0  # 2026-10-28T08:00:00Z

CONN_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
               "duration", "orig_bytes", "resp_bytes", "conn_state", "history"]
DNS_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "query",
              "qtype_name", "rcode_name"]
conn, dns = [], []
_uid = 0


def uid():
    global _uid
    _uid += 1
    return f"C{_uid:08x}"


def c(ts, s, sp, d, dp, proto="tcp", svc="-", dur=0.5, ob=500, rb=1500, st="SF", hist="ShADadFf"):
    conn.append([f"{ts:.6f}", uid(), s, str(sp), d, str(dp), proto, svc, f"{dur:.3f}", str(ob), str(rb), st, hist])


def q(ts, s, name, qt="A"):
    dns.append([f"{ts:.6f}", uid(), s, str(random.randint(30000, 60000)), "10.10.0.53", "53", "udp", name, qt, "NOERROR"])


# --- Normal activity (8 hours) ---------------------------------------------
sites = [f"192.0.2.{i}" for i in range(20, 60)]
names = ["www.office.example", "login.identity.example", "cdn.news.example", "api.crm.example",
         "updates.vendor.example", "mail.corp.example", "teams.chat.example"]
for _ in range(3000):
    ts = T0 + random.uniform(0, 8 * 3600)
    src = f"10.10.20.{random.randint(10, 120)}"
    c(ts, src, random.randint(49152, 65535), random.choice(sites), random.choice([443, 443, 443, 80]),
      svc="ssl", dur=random.uniform(0.1, 30), ob=random.randint(400, 20000), rb=random.randint(2000, 900000))
    q(ts - 0.05, src, random.choice(names))
# Legit periodic check-in to an allow-listed update server (should NOT alert)
for i in range(96):
    c(T0 + i * 300, "10.10.20.15", 50000 + i, "192.0.2.10", 443, svc="ssl", ob=800, rb=1200)

# --- Scenario A: external vertical port scan of DMZ web server -------------
for p in range(1, 1025):
    st = "SF" if p in (80, 443) else random.choice(["S0", "REJ"])
    c(T0 + 3600 + p * 0.02, "203.0.113.50", 61000, "10.10.1.10", p, dur=0, ob=0, rb=0, st=st, hist="S")

# --- Scenario B: internal SMB sweep (lateral movement discovery) -----------
for h in range(1, 61):
    c(T0 + 7200 + h * 0.5, "10.10.20.66", 52000 + h, f"10.10.20.{h}", 445, dur=0.01, ob=0, rb=0,
      st=random.choice(["S0", "REJ", "SF"]), hist="S")

# --- Scenario C: C2 beacon every ~60s with tiny jitter ---------------------
for i in range(90):
    c(T0 + 1800 + i * 60 + random.uniform(-2, 2), "10.10.20.31", 55000 + i, "198.51.100.66", 443,
      svc="ssl", dur=0.3, ob=random.randint(310, 330), rb=random.randint(180, 200))

# --- Scenario D: large outbound transfer (exfiltration) --------------------
for i in range(9):
    c(T0 + 5 * 3600 + i * 120, "10.10.30.12", 58000 + i, "203.0.113.200", 443, svc="ssl", dur=110,
      ob=random.randint(48_000_000, 55_000_000), rb=random.randint(20_000, 40_000))

# --- Scenario E: policy violations ------------------------------------------
for i in range(3):
    c(T0 + 4 * 3600 + i * 30, "10.10.20.44", 53000 + i, "198.51.100.150", 445, svc="smb", ob=2000, rb=3000)
for i in range(4):
    c(T0 + 6 * 3600 + i * 600, "198.51.100.201", 40000 + i, "10.10.1.20", 3389, svc="rdp", dur=900,
      ob=250000, rb=4_000_000)

# --- Scenario F: DNS tunneling from the beaconing host ---------------------
secret = ("employee_id,name,ssn_last4,salary\n" * 40).encode()
chunks = base64.b32encode(secret).decode().rstrip("=").lower()
for i in range(0, min(len(chunks), 63 * 60), 63):
    q(T0 + 2 * 3600 + i / 10, "10.10.20.31", f"{chunks[i:i+63]}.{i//63:04d}.c2.example", "TXT")


def write(name, path_name, fields, rows):
    rows.sort(key=lambda r: float(r[0]))
    with (OUT / name).open("w") as fh:
        fh.write("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n")
        fh.write(f"#path\t{path_name}\n#fields\t" + "\t".join(fields) + "\n")
        for r in rows:
            fh.write("\t".join(r) + "\n")


write("conn.log", "conn", CONN_FIELDS, conn)
write("dns.log", "dns", DNS_FIELDS, dns)
print(f"[+] conn.log: {len(conn)} flows, dns.log: {len(dns)} queries")
