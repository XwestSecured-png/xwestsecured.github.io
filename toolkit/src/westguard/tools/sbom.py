#!/usr/bin/env python3
"""
SBOM generator: produces a CycloneDX 1.6 JSON Software Bill of Materials from
Python (requirements*.txt) and Node.js (package-lock.json v2/v3) manifests.

  * Every component gets a Package URL (purl), the identifier OSV, Dependency-Track,
    GitHub and most scanners use.
  * Unpinned requirements (>=, ~=, no version) are recorded with a warning property,
    because reproducible builds need pinned, ideally hash-locked, versions.
  * Output is deterministic (sorted), so the SBOM can be diffed in code review.

    python3 supplychain/sbom.py sample_app --name sample-app --version 1.4.2 --out reports/sbom.cdx.json

Maps to: NIST SP 800-218 (SSDF) PS.3.2, EO 14028 SBOM minimum elements (NTIA), OWASP A03:2025
Author: Xiome West | License: MIT
"""
from __future__ import annotations

import argparse
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(==|>=|<=|~=|!=|>|<)?\s*([^;#\s]*)")


def norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()  # PEP 503


def parse_requirements(p: Path) -> list[dict]:
    comps = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = REQ_LINE.match(line)
        if not m:
            continue
        name, op, ver = norm_py(m.group(1)), m.group(2), m.group(3)
        pinned = op == "=="
        c = {"type": "library", "name": name, "version": ver if pinned else "",
             "purl": f"pkg:pypi/{name}@{ver}" if pinned else f"pkg:pypi/{name}",
             "bom-ref": f"pkg:pypi/{name}@{ver}" if pinned else f"pkg:pypi/{name}",
             "properties": [{"name": "source", "value": p.name}]}
        if not pinned:
            c["properties"].append({"name": "warning", "value": f"unpinned requirement '{line}'"})
        comps.append(c)
    return comps


def parse_package_lock(p: Path) -> list[dict]:
    data = json.loads(p.read_text(encoding="utf-8"))
    comps = []
    for path, meta in (data.get("packages") or {}).items():
        if not path:  # root project
            continue
        name = meta.get("name") or path.split("node_modules/")[-1]
        ver = meta.get("version", "")
        enc = name.replace("@", "%40", 1) if name.startswith("@") else name
        c = {"type": "library", "name": name, "version": ver, "purl": f"pkg:npm/{enc}@{ver}",
             "bom-ref": f"pkg:npm/{enc}@{ver}", "properties": [{"name": "source", "value": p.name}]}
        if meta.get("integrity"):
            alg, _, digest = meta["integrity"].partition("-")
            c["properties"].append({"name": "integrity", "value": meta["integrity"]})
        if meta.get("dev"):
            c["scope"] = "excluded"
        if meta.get("license"):
            c["licenses"] = [{"license": {"id": meta["license"]}}]
        comps.append(c)
    return comps


def build(root: Path, name: str, version: str) -> dict:
    comps = []
    for req in sorted(root.rglob("requirements*.txt")):
        comps += parse_requirements(req)
    for lock in sorted(root.rglob("package-lock.json")):
        if "node_modules" not in lock.parts:
            comps += parse_package_lock(lock)
    seen, uniq = set(), []
    for c in sorted(comps, key=lambda c: c["bom-ref"]):
        if c["bom-ref"] not in seen:
            seen.add(c["bom-ref"]); uniq.append(c)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, name + version)}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "tools": {"components": [{"type": "application", "name": "sbom.py", "version": "1.0.0"}]},
            "component": {"type": "application", "name": name, "version": version,
                          "bom-ref": f"{name}@{version}"},
        },
        "components": uniq,
        "dependencies": [{"ref": f"{name}@{version}", "dependsOn": [c["bom-ref"] for c in uniq]}],
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="CycloneDX SBOM generator")
    ap.add_argument("path", type=Path)
    ap.add_argument("--name", default="application")
    ap.add_argument("--version", default="0.0.0")
    ap.add_argument("--out", type=Path, default=Path("sbom.cdx.json"))
    a = ap.parse_args(argv)
    bom = build(a.path, a.name, a.version)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(bom, indent=2), encoding="utf-8")
    unpinned = [c["name"] for c in bom["components"] if any(p["name"] == "warning" for p in c.get("properties", []))]
    eco = {}
    for c in bom["components"]:
        e = c["purl"].split("/")[0].split(":")[1]
        eco[e] = eco.get(e, 0) + 1
    print(f"[+] SBOM: {len(bom['components'])} components {eco} -> {a.out}")
    if unpinned:
        print(f"[!] Unpinned: {', '.join(unpinned)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
