#!/usr/bin/env python3
"""
Score a tabletop exercise against expected actions and draft the after-action report (AAR).

    python3 tabletop/score_exercise.py tabletop/ransomware_exercise.json tabletop/sample_responses.json --out reports/
Author: Xiome West | License: MIT
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

HUMAN = lambda s: s.replace("_", " ")  # noqa: E731


def score(exercise: dict, responses: dict) -> dict:
    per, by_phase = [], defaultdict(lambda: [0, 0])
    for inj in exercise["injects"]:
        got = set(responses["responses"].get(str(inj["id"]), []))
        exp = inj["expected"]
        hit = [e for e in exp if e in got]
        miss = [e for e in exp if e not in got]
        pct = round(100 * len(hit) / len(exp))
        per.append({"id": inj["id"], "t": inj["t"], "phase": inj["phase"], "nist": inj["nist"], "pct": pct,
                    "hit": hit, "missed": miss, "note": responses.get("notes", {}).get(str(inj["id"]), "")})
        by_phase[inj["phase"]][0] += len(hit); by_phase[inj["phase"]][1] += len(exp)
    phases = {p: round(100 * h / t) for p, (h, t) in by_phase.items()}
    overall = round(100 * sum(h for h, _ in by_phase.values()) / sum(t for _, t in by_phase.values()))
    return {"overall": overall, "phases": phases, "injects": per}


def rating(p):
    return "Strong" if p >= 85 else "Adequate" if p >= 65 else "Needs improvement"


def aar(ex, resp, r) -> str:
    L = [f"# After-Action Report: {ex['title']}", "",
         f"**Exercise date:** {resp['exercise_date']}  ·  **Participants:** {resp['team']}  ·  **Format:** discussion-based tabletop (HSEEP style)", "",
         "## Summary", "",
         f"Overall coverage of expected actions: **{r['overall']}% ({rating(r['overall'])})**.", "",
         "| Phase (NIST SP 800-61r3 / CSF 2.0) | Coverage | Rating |", "|---|---|---|"]
    L += [f"| {p} | {v}% | {rating(v)} |" for p, v in r["phases"].items()]
    L += ["", "## Inject-by-inject results", "", "| # | Time | Phase | Coverage | Missed actions | Observation |", "|---|---|---|---|---|---|"]
    L += [f"| {i['id']} | {i['t']} | {i['phase']} | {i['pct']}% | {', '.join(map(HUMAN, i['missed'])) or '—'} | {i['note'] or '—'} |" for i in r["injects"]]
    gaps = [(i, m) for i in r["injects"] for m in i["missed"]]
    L += ["", "## Improvement plan", "",
          "Each missed action becomes a tracked item. Owners and dates are filled in at the hot wash.", "",
          "| # | Improvement | Source inject | CSF function | Owner | Due |", "|---|---|---|---|---|---|"]
    L += [f"| IP-{n:02d} | {HUMAN(m).capitalize()} | {i['id']} ({i['t']}) | {i['nist']} | _TBD_ | _TBD_ |" for n, (i, m) in enumerate(gaps, 1)]
    L += ["", "## Strengths", ""] + [f"- Inject {i['id']}: {', '.join(map(HUMAN, i['hit']))}" for i in r["injects"] if i["pct"] >= 75]
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("exercise", type=Path); ap.add_argument("responses", type=Path)
    ap.add_argument("--out", type=Path, default=Path("reports")); a = ap.parse_args(argv)
    ex, resp = json.loads(a.exercise.read_text()), json.loads(a.responses.read_text())
    r = score(ex, resp)
    print(f"Overall: {r['overall']}% ({rating(r['overall'])})")
    for p, v in r["phases"].items():
        print(f"  {p:<22} {v:>3}%  {rating(v)}")
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "tabletop_aar.md").write_text(aar(ex, resp, r))
    return r


if __name__ == "__main__":
    main()
