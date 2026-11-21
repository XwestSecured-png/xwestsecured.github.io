#!/usr/bin/env python3
"""Measure the injection detector on a labelled dataset: precision, recall, F1, and every miss.

    python3 llm_guard/evaluate.py --data data/prompt_injection_eval.jsonl --out reports/
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard import detect_injection  # noqa: E402


def evaluate(rows):
    tp = fp = tn = fn = 0; errors = []
    for r in rows:
        d = detect_injection(r["text"]); pred = int(d["flagged"])
        if pred and r["label"]: tp += 1
        elif pred: fp += 1; errors.append(("false_positive", r["text"], d))
        elif r["label"]: fn += 1; errors.append(("false_negative", r["text"], d))
        else: tn += 1
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": round(prec, 3), "recall": round(rec, 3),
            "f1": round(f1, 3)}, errors


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, default=Path("data/prompt_injection_eval.jsonl"))
    ap.add_argument("--out", type=Path, default=Path("reports")); a = ap.parse_args(argv)
    rows = [json.loads(l) for l in a.data.read_text().splitlines() if l.strip()]
    m, errors = evaluate(rows)
    print(f"samples={len(rows)}  TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']}")
    print(f"precision={m['precision']}  recall={m['recall']}  F1={m['f1']}")
    for kind, text, d in errors:
        print(f"  {kind:<15} score={d['score']} {text[:90]}")
    a.out.mkdir(parents=True, exist_ok=True)
    md = ["# Prompt-Injection Detector Evaluation", "",
          f"Dataset: `{a.data.name}` ({len(rows)} prompts: {m['tp']+m['fn']} injections, {m['tn']+m['fp']} benign, "
          "including benign prompts that reuse attack words such as *ignore*, *override*, *act as*, *repeat*).", "",
          "| Metric | Value |", "|---|---|"] + [f"| {k} | {v} |" for k, v in m.items()] + ["", "## Errors", "",
          "| Type | Score | Prompt |", "|---|---|---|"] + [f"| {k} | {d['score']} | {t[:100]} |" for k, t, d in errors] + [
          "", "False negatives are paraphrased or translated attacks. That is expected of any pattern detector and is the "
          "reason the agent **policy layer** (tool allow-list, per-user authorization, egress allow-list, human approval) "
          "is the control that actually limits damage. See scenario S6 in `agent_simulation.md`.", "",
          "**Caveat:** the signal weights were tuned while looking at this dataset, so these numbers are optimistic. "
          "A real evaluation needs a held-out set (for example a public prompt-injection benchmark) and ongoing red-teaming."]
    (a.out / "detector_eval.md").write_text("\n".join(md) + "\n")
    (a.out / "detector_eval.json").write_text(json.dumps({"metrics": m, "errors": [(k, t) for k, t, _ in errors]}, indent=2))
    return m


if __name__ == "__main__":
    main()
