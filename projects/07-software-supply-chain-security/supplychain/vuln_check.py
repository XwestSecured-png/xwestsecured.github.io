#!/usr/bin/env python3
"""
Dependency vulnerability check: reads a CycloneDX SBOM and looks up every purl
in the OSV.dev database (aggregates GitHub Security Advisories, PyPA, npm, Go,
RubyGems, Maven, NuGet, crates.io and more), then applies a build policy.

    # live (needs HTTPS egress to api.osv.dev)
    python3 supplychain/vuln_check.py reports/sbom.cdx.json --fetch
    # live from package registries (PyPI JSON API + npm bulk advisory API); often allowed
    # through corporate proxies that block other sites. --save-db snapshots results.
    python3 supplychain/vuln_check.py reports/sbom.cdx.json --registry --save-db snapshot.json
    # offline / air-gapped (a snapshot in OSV format)
    python3 supplychain/vuln_check.py reports/sbom.cdx.json --osv sample_data/vuln_db_snapshot.json

Policy (exit code 1 = fail the build):
  * any CRITICAL/HIGH vulnerability with a fix available
  * any UNRATED vulnerability with a fix available (treated as HIGH until triaged)
  * any component listed in CISA KEV (pass --kev)
  * any unpinned dependency when --strict

Maps to: OWASP A03:2025 Software Supply Chain Failures, NIST SSDF RV.1/RV.2, CIS Control 16.4
Author: Xiome West | License: MIT
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
SEV = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def fetch_osv(purls: list[str]) -> dict:
    """Return {purl: [vuln, ...]} using OSV querybatch + per-vuln details."""
    out = {}
    for i in range(0, len(purls), 500):
        chunk = purls[i:i + 500]
        body = json.dumps({"queries": [{"package": {"purl": p}} for p in chunk]}).encode()
        req = urllib.request.Request(OSV_BATCH, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as r:  # nosec - fixed https endpoint
            results = json.load(r)["results"]
        for purl, res in zip(chunk, results):
            vulns = []
            for v in res.get("vulns", []):
                with urllib.request.urlopen(OSV_VULN.format(id=v["id"]), timeout=30) as r:  # nosec
                    vulns.append(json.load(r))
            out[purl] = vulns
    return out


def fetch_registries(comps: list[dict]) -> dict:
    """PyPI + npm advisory lookups, normalized to OSV-style records."""
    out = {}
    npm_q = {}
    for c in comps:
        eco = c["purl"].split("/")[0].split(":")[1]
        if eco == "pypi":
            url = f"https://pypi.org/pypi/{c['name']}/{c['version']}/json"
            with urllib.request.urlopen(url, timeout=30) as r:  # nosec - fixed https endpoint
                vulns = json.load(r).get("vulnerabilities", [])
            recs, seen = [], set()
            for v in vulns:          # PyPI lists PYSEC and GHSA twins; keep one per CVE set
                key = tuple(sorted(x for x in [v["id"], *v.get("aliases", [])] if x.startswith("CVE-"))) or (v["id"],)
                if key in seen:
                    continue
                seen.add(key)
                recs.append({"id": v["id"], "aliases": v.get("aliases", []),
                             "summary": (v.get("summary") or v.get("details") or "").strip().splitlines()[0],
                             "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": f} for f in v.get("fixed_in", [])]}]}],
                             "database_specific": {"severity": "UNKNOWN", "source": "pypi"}})
            out[c["purl"]] = recs
        elif eco == "npm":
            npm_q.setdefault(c["name"], []).append(c)
    if npm_q:
        body = json.dumps({n: [c["version"] for c in cs] for n, cs in npm_q.items()}).encode()
        req = urllib.request.Request("https://registry.npmjs.org/-/npm/v1/security/advisories/bulk", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as r:  # nosec
            adv = json.load(r)
        import re
        for name, cs in npm_q.items():
            for c in cs:
                recs = []
                for a in adv.get(name, []):
                    vv = a.get("vulnerable_versions", "")
                    m = re.search(r"(<=?)\s*([0-9][^\s,|]*)\s*$", vv)
                    ev = [] if not m else [{"fixed": m.group(2)} if m.group(1) == "<" else {"last_affected": m.group(2)}]
                    recs.append({"id": a["url"].rsplit("/", 1)[-1], "aliases": [], "summary": a.get("title", ""),
                                 "affected": [{"ranges": [{"type": "SEMVER", "events": ev}]}],
                                 "database_specific": {"severity": a.get("severity", "unknown").upper(),
                                                       "cvss": (a.get("cvss") or {}).get("score"), "source": "npm",
                                                       "vulnerable_versions": a.get("vulnerable_versions")}})
                out[c["purl"]] = recs
    return out


def summarize(v: dict, version: str) -> dict:
    sev = (v.get("database_specific") or {}).get("severity", "UNKNOWN").upper()
    fixed = sorted({e["fixed"] for a in v.get("affected", []) for r in a.get("ranges", [])
                    for e in r.get("events", []) if "fixed" in e})
    last = sorted({e["last_affected"] for a in v.get("affected", []) for r in a.get("ranges", [])
                   for e in r.get("events", []) if "last_affected" in e})
    cves = [x for x in v.get("aliases", []) if x.startswith("CVE-")]
    return {"id": v["id"], "cves": cves, "severity": sev, "summary": v.get("summary", "")[:120],
            "fixed_in": fixed, "last_affected": last, "installed": version}


def vkey(v: str) -> tuple:
    import re
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


def upgrade_plan(rows: list[dict]) -> list[dict]:
    plan = {}
    for r in rows:
        p = plan.setdefault(r["component"], {"component": r["component"], "installed": r["installed"], "vulns": 0,
                                             "worst": "UNKNOWN", "fixed": [], "last": []})
        p["vulns"] += 1
        if SEV.get(r["severity"], 4) < SEV.get(p["worst"], 4) or p["worst"] == "UNKNOWN":
            p["worst"] = r["severity"] if r["severity"] != "UNKNOWN" or p["worst"] == "UNKNOWN" else p["worst"]
        p["fixed"] += r["fixed_in"]
        p["last"] += r["last_affected"]
    out = []
    for p in plan.values():
        target = max(p["fixed"], key=vkey) if p["fixed"] else None
        top_last = max(p["last"], key=vkey) if p["last"] else None
        if top_last and (not target or vkey(top_last) >= vkey(target)):
            rec = f"latest (> {top_last})"
        else:
            rec = f">= {target}" if target else "no fix published; replace or mitigate"
        out.append({"component": p["component"], "installed": p["installed"], "vulnerabilities": p["vulns"],
                    "worst_severity": p["worst"], "upgrade_to": rec})
    return sorted(out, key=lambda x: (SEV.get(x["worst_severity"], 4), -x["vulnerabilities"]))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="SBOM -> OSV vulnerability check with build policy")
    ap.add_argument("sbom", type=Path)
    ap.add_argument("--fetch", action="store_true", help="query api.osv.dev")
    ap.add_argument("--registry", action="store_true", help="query PyPI + npm advisory APIs")
    ap.add_argument("--osv", type=Path, help="offline OSV-format snapshot {purl: [osv records]}")
    ap.add_argument("--save-db", type=Path, help="write fetched records as an offline snapshot")
    ap.add_argument("--kev", type=Path, help="CISA KEV JSON to flag actively exploited CVEs")
    ap.add_argument("--strict", action="store_true", help="fail on unpinned dependencies")
    ap.add_argument("--out", type=Path)
    a = ap.parse_args(argv)

    bom = json.loads(a.sbom.read_text(encoding="utf-8"))
    comps = bom.get("components", [])
    pinned = [c for c in comps if c.get("version")]
    unpinned = [c for c in comps if not c.get("version")]
    if a.fetch:
        db = fetch_osv([c["purl"] for c in pinned])
    elif a.registry:
        db = fetch_registries(pinned)
    else:
        db = json.loads(a.osv.read_text(encoding="utf-8")) if a.osv else {}
    if a.save_db:
        a.save_db.write_text(json.dumps(db, indent=1), encoding="utf-8")
    kev = set()
    if a.kev:
        kev = {x["cveID"] for x in json.loads(a.kev.read_text())["vulnerabilities"]}

    rows = []
    for c in pinned:
        for v in db.get(c["purl"], []):
            s = summarize(v, c["version"])
            s.update(component=c["name"], purl=c["purl"], kev=bool(set(s["cves"]) & kev))
            rows.append(s)
    rows.sort(key=lambda r: (not r["kev"], SEV.get(r["severity"], 4), r["component"]))

    fail_reasons = []
    for r in rows:
        if r["kev"]:
            fail_reasons.append(f"{r['component']} {r['id']} is in CISA KEV")
        elif r["severity"] in ("CRITICAL", "HIGH", "UNKNOWN") and (r["fixed_in"] or r["last_affected"]):
            fail_reasons.append(f"{r['component']}@{r['installed']} {r['severity']} {r['id']}")
    if a.strict:
        fail_reasons += [f"{c['name']} is unpinned" for c in unpinned]

    plan = upgrade_plan(rows)
    print(f"[+] {len(pinned)} pinned components checked, {len(rows)} known vulnerabilities, {len(unpinned)} unpinned")
    print(f"    {'component':<12} {'installed':<10} {'vulns':>5}  {'worst':<9} upgrade to")
    for p in plan:
        print(f"    {p['component']:<12} {p['installed']:<10} {p['vulnerabilities']:>5}  {p['worst_severity']:<9} {p['upgrade_to']}")
    for c in unpinned:
        print(f"    [POLICY] {c['name']} is not pinned to an exact version")
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps({"upgrade_plan": plan, "vulnerabilities": rows,
                                     "unpinned": [c["name"] for c in unpinned],
                                     "policy_failures": fail_reasons}, indent=2), encoding="utf-8")
        md = ["# Dependency Vulnerability Report", "",
              f"**Policy: {'FAIL' if fail_reasons else 'PASS'}** · {len(pinned)} pinned components · "
              f"{len(rows)} known vulnerabilities · {len(unpinned)} unpinned", "",
              "## Upgrade plan", "", "| Component | Installed | Vulns | Worst severity | Upgrade to |", "|---|---|---|---|---|"]
        md += [f"| {p['component']} | {p['installed']} | {p['vulnerabilities']} | {p['worst_severity']} | {p['upgrade_to']} |" for p in plan]
        md += ["", "## All advisories", "", "| Component | Advisory | CVE | Severity | Fixed in | Summary |", "|---|---|---|---|---|---|"]
        md += [f"| {r['component']}@{r['installed']} | {r['id']} | {', '.join(r['cves']) or '-'} | {r['severity']} | "
               f"{', '.join(r['fixed_in']) or ('> ' + r['last_affected'][-1] if r['last_affected'] else 'none')} | "
               f"{r['summary'].replace('|', '/')} |" for r in rows]
        if unpinned:
            md += ["", "## Unpinned dependencies", ""] + [f"- `{c['name']}`" for c in unpinned]
        a.out.with_suffix(".md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"[{'✗' if fail_reasons else '✓'}] Policy: {'FAIL' if fail_reasons else 'PASS'} "
          f"({len(fail_reasons) - (len(unpinned) if a.strict else 0)} blocking advisories{', ' + str(len(unpinned)) + ' unpinned' if a.strict and unpinned else ''})")
    return 1 if fail_reasons else 0


if __name__ == "__main__":
    sys.exit(main())
