#!/usr/bin/env python3
"""
CVSS v3.1 base-score calculator (FIRST specification, section 7 formulas incl. Roundup).

    python3 cvss.py "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
"""
import math
import sys

W = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
     "UI": {"N": 0.85, "R": 0.62}, "CIA": {"H": 0.56, "L": 0.22, "N": 0.0}}
PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def roundup(x: float) -> float:
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def parse(vector: str) -> dict:
    parts = vector.split("/")
    if not parts[0].startswith("CVSS:3."):
        raise ValueError("expected CVSS:3.x vector")
    m = dict(p.split(":") for p in parts[1:])
    for k in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
        if k not in m:
            raise ValueError(f"missing metric {k}")
    return m


def base_score(vector: str) -> float:
    m = parse(vector)
    iss = 1 - (1 - W["CIA"][m["C"]]) * (1 - W["CIA"][m["I"]]) * (1 - W["CIA"][m["A"]])
    changed = m["S"] == "C"
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    expl = 8.22 * W["AV"][m["AV"]] * W["AC"][m["AC"]] * PR[m["S"]][m["PR"]] * W["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    return roundup(min(1.08 * (impact + expl), 10)) if changed else roundup(min(impact + expl, 10))


def severity(score: float) -> str:
    return "None" if score == 0 else "Low" if score < 4 else "Medium" if score < 7 else "High" if score < 9 else "Critical"


if __name__ == "__main__":
    for v in sys.argv[1:]:
        s = base_score(v)
        print(f"{s:4.1f} {severity(s):<8} {v}")
