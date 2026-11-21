#!/usr/bin/env python3
"""Export every rule to Sigma YAML (sigma/<id>.yml). Correlation rules are emitted as a
base rule plus a Sigma correlation rule (Sigma spec v2). No PyYAML needed.

    python3 detections/export_sigma.py --out sigma/
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rules import RULES  # noqa: E402

NS = uuid.UUID("5b2c1d7e-3f4a-4e8b-9c6d-1a2b3c4d5e6f")


def q(v):
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return str(v)
    return json.dumps(str(v))          # JSON strings are valid YAML double-quoted scalars


def emit_detection(det: dict, ind="    ") -> list[str]:
    out = []
    for name, sel in det.items():
        if name == "condition":
            continue
        out.append(f"{ind}{name}:")
        for k, v in sel.items():
            if isinstance(v, list):
                out.append(f"{ind}    {k}:"); out += [f"{ind}        - {q(x)}" for x in v]
            else:
                out.append(f"{ind}    {k}: {q(v)}")
    out.append(f"{ind}condition: {det['condition']}")
    return out


def to_sigma(r: dict) -> str:
    rid = uuid.uuid5(NS, r["id"])
    L = [f"title: {r['title']}", f"id: {rid}", f"name: {r['id'].lower().replace('-', '_')}", "status: experimental",
         f"description: {q(r['description'])}", "author: Xiome West", "date: 2026-11-21",
         "references:", "    - https://attack.mitre.org/techniques/" + r["attack"][0].replace(".", "/") + "/",
         "tags:"] + [f"    - attack.{t.lower()}" for t in r["attack"]] + [
         "logsource:", f"    product: {r['logsource']['product']}", f"    service: {r['logsource']['service']}",
         "detection:"] + emit_detection(r["detection"]) + ["falsepositives:"] + [f"    - {q(f)}" for f in r["falsepositives"]] + [f"level: {r['level']}"]
    if "correlation" in r:
        c = r["correlation"]
        L += ["---", f"title: {r['title']} (correlation)", f"id: {uuid.uuid5(NS, r['id'] + '-corr')}", "status: experimental",
              "correlation:", f"    type: {c['type']}", "    rules:", f"        - {r['id'].lower().replace('-', '_')}",
              "    group-by:"] + [f"        - {g}" for g in c["group_by"]] + [f"    timespan: {c['timespan_s'] // 60}m", "    condition:",
              f"        gte: {c['gte']}"] + ([f"        field: {c['field']}"] if c["type"] == "value_count" else []) + [f"level: {r['level']}"]
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("--out", type=Path, default=Path("sigma")); a = ap.parse_args(argv)
    a.out.mkdir(parents=True, exist_ok=True); n = 0
    for r in RULES:
        if "python_only" in r:
            print(f"  skip {r['id']} (python only: {r['python_only'][:60]}...)"); continue
        (a.out / f"{r['id'].lower()}.yml").write_text(to_sigma(r)); n += 1
    print(f"wrote {n} Sigma rules to {a.out}/")


if __name__ == "__main__":
    main()
