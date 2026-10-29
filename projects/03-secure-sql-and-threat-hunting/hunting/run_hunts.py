#!/usr/bin/env python3
"""
Execute every hunt in threat_hunting_queries.sql against a database (read-only)
and write a Markdown hunt report.

    python3 hunting/run_hunts.py --db lab/soc_lab.db --out reports/hunt_report.md
"""
import argparse
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent


def parse_hunts(sql_text: str):
    blocks = re.split(r"^-- name:\s*", sql_text, flags=re.M)[1:]
    for b in blocks:
        title, _, body = b.partition("\n")
        why = re.search(r"^-- why:\s*(.+)$", body, re.M)
        query = "\n".join(l for l in body.splitlines() if not l.strip().startswith("--")).strip()
        yield title.strip(), (why.group(1) if why else ""), query


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--sql", default=str(HERE / "threat_hunting_queries.sql"))
    ap.add_argument("--out", default="reports/hunt_report.md")
    ap.add_argument("--max-rows", type=int, default=15)
    a = ap.parse_args()

    con = sqlite3.connect(f"file:{a.db}?mode=ro", uri=True)   # least privilege
    md = ["# Threat Hunt Report", "",
          f"*Database:* `{Path(a.db).name}` · *Run:* {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}", ""]
    summary = []
    for title, why, q in parse_hunts(Path(a.sql).read_text(encoding="utf-8")):
        cur = con.execute(q)
        cols = [c[0] for c in cur.description]
        rows = cur.fetchall()
        summary.append((title, len(rows)))
        md += [f"## {title}", "", f"_{why}_", "", f"**Rows returned:** {len(rows)}", ""]
        if rows:
            md.append("| " + " | ".join(cols) + " |")
            md.append("|" + "---|" * len(cols))
            for r in rows[: a.max_rows]:
                md.append("| " + " | ".join(str(v).replace("|", "\\|") for v in r) + " |")
            if len(rows) > a.max_rows:
                md.append(f"\n…{len(rows) - a.max_rows} more rows")
        md.append("")
    md[4:4] = ["## Summary", "", "| Hunt | Rows |", "|---|---|",
               *[f"| {t} | {n} |" for t, n in summary], ""]
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text("\n".join(md), encoding="utf-8")
    for t, n in summary:
        print(f"  {n:4d}  {t}")
    print(f"[+] {a.out}")


if __name__ == "__main__":
    main()
