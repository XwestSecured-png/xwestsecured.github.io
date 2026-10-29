#!/usr/bin/env python3
"""
NIST CSF 2.0 Gap Assessment & Risk Register Reporter
====================================================

Inputs
  assessment/csf2_profile.csv  Current vs. target maturity (0-4) for all 22 CSF 2.0
                               categories, with a business weight, owner and evidence.
  risk/risk_register.csv       Inherent and residual likelihood x impact (1-5) per risk.
  config.json                  Organization name, risk appetite and scoring bands.

Outputs (reports/)
  grc_report.md     Board/executive summary + prioritized roadmap (Markdown)
  grc_report.html   Same content, self-contained HTML with SVG charts (print to PDF)
  roadmap.csv       Prioritized improvement backlog

Maturity scale (per category, an organizational "Current" vs. "Target" CSF Profile)
  0 Not implemented · 1 Partial · 2 Risk Informed · 3 Repeatable · 4 Adaptive
  (levels 1-4 borrow the CSF 2.0 Tier names, applied per category)

Author: Xiome West | License: MIT
"""
from __future__ import annotations

import argparse
import csv
import html
import json
from collections import defaultdict
from pathlib import Path

FUNCTIONS = ["Govern", "Identify", "Protect", "Detect", "Respond", "Recover"]
LEVELS = {0: "Not implemented", 1: "Partial", 2: "Risk Informed", 3: "Repeatable", 4: "Adaptive"}
BAND_COLORS = {"low": "#2e7d32", "medium": "#f9a825", "high": "#ef6c00", "critical": "#c62828"}


def load_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def band(score: int, bands: dict) -> str:
    for name, (lo, hi) in bands.items():
        if lo <= score <= hi:
            return name
    return "critical"


def analyze(profile, risks, cfg):
    # ---- CSF gaps
    cats = []
    for r in profile:
        cur, tgt, w = int(r["current"]), int(r["target"]), float(r.get("weight") or 1)
        cats.append({**r, "current": cur, "target": tgt, "weight": w, "gap": max(tgt - cur, 0),
                     "priority_score": round(max(tgt - cur, 0) * w, 2)})
    by_fn = defaultdict(list)
    for c in cats:
        by_fn[c["function"]].append(c)
    fn_summary = {f: {"current": round(sum(c["current"] for c in by_fn[f]) / len(by_fn[f]), 2),
                      "target": round(sum(c["target"] for c in by_fn[f]) / len(by_fn[f]), 2),
                      "categories": len(by_fn[f])} for f in FUNCTIONS if by_fn[f]}
    roadmap = sorted([c for c in cats if c["gap"] > 0], key=lambda c: -c["priority_score"])
    for i, c in enumerate(roadmap):
        c["phase"] = "0-90 days" if i < 5 else ("3-6 months" if i < 12 else "6-12 months")

    # ---- Risks
    bands, appetite = cfg["risk_bands"], cfg["risk_appetite_max_residual"]
    rr = []
    for r in risks:
        inh = int(r["likelihood"]) * int(r["impact"])
        res = int(r["residual_likelihood"]) * int(r["residual_impact"])
        rr.append({**r, "inherent": inh, "inherent_band": band(inh, bands), "residual": res,
                   "residual_band": band(res, bands), "within_appetite": res <= appetite,
                   "reduction_pct": round((inh - res) / inh * 100) if inh else 0})
    rr.sort(key=lambda r: -r["inherent"])
    return cats, fn_summary, roadmap, rr


# --------------------------------------------------------------------------- #
# SVG charts (no external libraries, render in GitHub and browsers)
# --------------------------------------------------------------------------- #

def svg_function_bars(fn_summary) -> str:
    w, h, left, top, bar_h, gap = 560, 300, 90, 30, 14, 14
    scale = (w - left - 30) / 4
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" role="img" '
             f'aria-label="CSF 2.0 current vs target maturity by function" font-family="system-ui,sans-serif" font-size="12">',
             '<rect width="100%" height="100%" fill="#ffffff"/>']
    for lvl in range(5):
        x = left + lvl * scale
        parts.append(f'<line x1="{x}" y1="{top - 8}" x2="{x}" y2="{h - 30}" stroke="#e0e0e0"/>'
                     f'<text x="{x}" y="{h - 14}" text-anchor="middle" fill="#555">{lvl}</text>')
    for i, (fn, s) in enumerate(fn_summary.items()):
        y = top + i * (2 * bar_h + gap)
        parts.append(f'<text x="{left - 8}" y="{y + bar_h + 4}" text-anchor="end" fill="#222">{fn}</text>')
        parts.append(f'<rect x="{left}" y="{y}" width="{s["current"] * scale:.1f}" height="{bar_h}" fill="#1565c0"/>'
                     f'<text x="{left + s["current"] * scale + 4:.1f}" y="{y + 11}" fill="#1565c0">{s["current"]}</text>')
        parts.append(f'<rect x="{left}" y="{y + bar_h}" width="{s["target"] * scale:.1f}" height="{bar_h}" fill="#90caf9"/>'
                     f'<text x="{left + s["target"] * scale + 4:.1f}" y="{y + bar_h + 11}" fill="#555">{s["target"]}</text>')
    parts.append(f'<rect x="{w - 170}" y="4" width="10" height="10" fill="#1565c0"/><text x="{w - 155}" y="13">Current</text>'
                 f'<rect x="{w - 95}" y="4" width="10" height="10" fill="#90caf9"/><text x="{w - 80}" y="13">Target</text></svg>')
    return "".join(parts)


def svg_heatmap(risks, key_l, key_i, title, bands) -> str:
    cell, left, top = 56, 70, 40
    w, h = left + 5 * cell + 20, top + 5 * cell + 50
    counts = defaultdict(list)
    for r in risks:
        counts[(int(r[key_l]), int(r[key_i]))].append(r["risk_id"])
    p = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" role="img" aria-label="{title}" '
         f'font-family="system-ui,sans-serif" font-size="11"><rect width="100%" height="100%" fill="#fff"/>',
         f'<text x="{left}" y="20" font-size="14" font-weight="600">{title}</text>']
    for li in range(1, 6):
        for im in range(1, 6):
            x, y = left + (im - 1) * cell, top + (5 - li) * cell
            color = BAND_COLORS[band(li * im, bands)]
            ids = counts.get((li, im), [])
            p.append(f'<rect x="{x}" y="{y}" width="{cell - 2}" height="{cell - 2}" fill="{color}" opacity="0.85"/>')
            for k, rid in enumerate(ids[:3]):
                p.append(f'<text x="{x + cell / 2 - 1}" y="{y + 18 + k * 13}" text-anchor="middle" fill="#fff" font-weight="600">{rid}</text>')
    for n in range(1, 6):
        p.append(f'<text x="{left - 8}" y="{top + (5 - n) * cell + cell / 2}" text-anchor="end">{n}</text>')
        p.append(f'<text x="{left + (n - 1) * cell + cell / 2}" y="{top + 5 * cell + 14}" text-anchor="middle">{n}</text>')
    p.append(f'<text x="{left + 2.5 * cell}" y="{h - 8}" text-anchor="middle" fill="#444">Impact →</text>')
    p.append(f'<text x="14" y="{top + 2.5 * cell}" transform="rotate(-90 14 {top + 2.5 * cell})" text-anchor="middle" fill="#444">Likelihood →</text></svg>')
    return "".join(p)


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #

def build_markdown(cfg, cats, fn_summary, roadmap, risks) -> str:
    overall_cur = round(sum(c["current"] for c in cats) / len(cats), 2)
    overall_tgt = round(sum(c["target"] for c in cats) / len(cats), 2)
    out_of_appetite = [r for r in risks if not r["within_appetite"]]
    md = [f"# Cybersecurity Program Assessment: {cfg['organization']}", "",
          f"*Framework:* NIST Cybersecurity Framework (CSF) 2.0 · *Assessment date:* {cfg['assessment_date']}  ",
          f"*Scale:* 0 Not implemented · 1 Partial · 2 Risk Informed · 3 Repeatable · 4 Adaptive", "",
          "## Executive summary", "",
          f"- **Overall maturity:** {overall_cur} / 4 today against a target of {overall_tgt}. "
          f"**{len(roadmap)} of {len(cats)}** CSF categories are below target.",
          f"- **Weakest function:** {min(fn_summary, key=lambda f: fn_summary[f]['current'])} "
          f"({min(s['current'] for s in fn_summary.values())}). "
          f"**Strongest:** {max(fn_summary, key=lambda f: fn_summary[f]['current'])}.",
          f"- **Top risks:** " + "; ".join(f"{r['risk_id']} {r['title']} ({r['inherent']}/25)" for r in risks[:3]) + ".",
          f"- After the planned controls, **{len(risks) - len(out_of_appetite)} of {len(risks)}** risks fall within the "
          f"approved appetite (residual ≤ {cfg['risk_appetite_max_residual']}). "
          + (f"**{len(out_of_appetite)}** still {'needs' if len(out_of_appetite) == 1 else 'need'} formal executive risk acceptance or additional controls: "
             + ", ".join(r["risk_id"] for r in out_of_appetite) + "." if out_of_appetite else ""),
          "", "![CSF function maturity](csf_functions.svg)", "",
          "## Maturity by CSF function", "", "| Function | Categories | Current | Target | Gap |", "|---|---|---|---|---|"]
    for f, s in fn_summary.items():
        md.append(f"| {f} | {s['categories']} | {s['current']} | {s['target']} | {round(s['target'] - s['current'], 2)} |")
    md += ["", "## Prioritized improvement roadmap", "",
           "Priority score = (target − current) × business weight. The top five items form the 90-day plan.", "",
           "| # | Phase | Category | Current → Target | Score | Owner | Evidence / gap |", "|---|---|---|---|---|---|---|"]
    for i, c in enumerate(roadmap, 1):
        md.append(f"| {i} | {c['phase']} | **{c['category_id']}** {c['category_name']} | {c['current']} → {c['target']} | "
                  f"{c['priority_score']} | {c['owner']} | {c['evidence']}{'; ' + c['notes'] if c['notes'] else ''} |")
    md += ["", "## Risk register", "",
           "| ID | Risk | Inherent (L×I) | Treatment | Residual | Reduction | Appetite | Owner | Due |", "|---|---|---|---|---|---|---|---|---|"]
    for r in risks:
        md.append(f"| {r['risk_id']} | {r['title']} | {r['likelihood']}×{r['impact']} = **{r['inherent']}** ({r['inherent_band']}) | "
                  f"{r['treatment']}: {r['planned_controls']} | {r['residual']} ({r['residual_band']}) | {r['reduction_pct']}% | "
                  f"{'✅' if r['within_appetite'] else '⚠️ exceeds'} | {r['owner']} | {r['due']} |")
    md += ["", "| Inherent risk | Residual risk (after planned controls) |", "|---|---|",
           "| ![Inherent](heatmap_inherent.svg) | ![Residual](heatmap_residual.svg) |", "",
           "## Recommended board reporting (quarterly)", "",
           "| KPI | Why it matters | CSF |", "|---|---|---|",
           "| % of accounts with phishing-resistant MFA (admins / all staff) | Account takeover is the top initial-access vector | PR.AA |",
           "| Open KEV vulnerabilities older than 7 days | Exploited-now exposure | ID.RA, PR.PS |",
           "| Days since last successful restore test | Ransomware recoverability | RC.RP |",
           "| Phishing simulation click rate / report rate | Human-layer resilience | PR.AT |",
           "| Critical vendors with a current security review | Third-party exposure | GV.SC |",
           "| Mean time to detect / contain (incidents) | Response effectiveness | DE.AE, RS.MA |", ""]
    return "\n".join(md)


def build_html(md_text: str, svgs: dict, cfg) -> str:
    """Minimal Markdown-to-HTML for our own controlled report (tables, headings, lists, bold)."""
    import re
    out, in_table = [], False
    for line in md_text.splitlines():
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if set("".join(cells)) <= set("-: "):
                continue
            tag = "th" if not in_table else "td"
            if not in_table:
                out.append("<table>"); in_table = True
            out.append("<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in cells) + "</tr>")
            continue
        if in_table:
            out.append("</table>"); in_table = False
        if line.startswith("# "):
            out.append(f"<h1>{line[2:]}</h1>")
        elif line.startswith("## "):
            out.append(f"<h2>{line[3:]}</h2>")
        elif line.startswith("- "):
            out.append(f"<li>{line[2:]}</li>")
        elif line.strip():
            out.append(f"<p>{line}</p>")
    if in_table:
        out.append("</table>")
    body = "\n".join(out)
    body = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", body)
    body = re.sub(r"\*(.+?)\*", r"<em>\1</em>", body)
    for name, svg in svgs.items():
        body = re.sub(r"!\[[^\]]*\]\(" + re.escape(name) + r"\)", svg, body)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CSF 2.0 Assessment: {html.escape(cfg['organization'])}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 16px;color:#1a1a1a;line-height:1.5}}
table{{border-collapse:collapse;width:100%;margin:1rem 0;font-size:.9rem}}th,td{{border:1px solid #ddd;padding:6px 8px;vertical-align:top}}
th{{background:#f3f6fa;text-align:left}}h1{{border-bottom:3px solid #1565c0;padding-bottom:.3rem}}h2{{margin-top:2rem;color:#0d47a1}}
svg{{max-width:640px;width:100%;height:auto;display:block}}td:has(svg){{width:50%}}@media print{{h2{{page-break-after:avoid}}table{{page-break-inside:auto}}}}</style></head>
<body>{body}<p><em>Generated by grc_report.py</em></p></body></html>"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="NIST CSF 2.0 gap assessment + risk register report")
    ap.add_argument("--profile", default="assessment/csf2_profile.csv", type=Path)
    ap.add_argument("--risks", default="risk/risk_register.csv", type=Path)
    ap.add_argument("--config", default="config.json", type=Path)
    ap.add_argument("--out", default="reports", type=Path)
    a = ap.parse_args(argv)

    cfg = json.loads(a.config.read_text(encoding="utf-8"))
    cats, fn_summary, roadmap, risks = analyze(load_csv(a.profile), load_csv(a.risks), cfg)
    a.out.mkdir(parents=True, exist_ok=True)
    svgs = {"csf_functions.svg": svg_function_bars(fn_summary),
            "heatmap_inherent.svg": svg_heatmap(risks, "likelihood", "impact", "Inherent risk", cfg["risk_bands"]),
            "heatmap_residual.svg": svg_heatmap(risks, "residual_likelihood", "residual_impact", "Residual risk", cfg["risk_bands"])}
    for name, svg in svgs.items():
        (a.out / name).write_text(svg, encoding="utf-8")
    md = build_markdown(cfg, cats, fn_summary, roadmap, risks)
    (a.out / "grc_report.md").write_text(md, encoding="utf-8")
    (a.out / "grc_report.html").write_text(build_html(md, svgs, cfg), encoding="utf-8")
    with (a.out / "roadmap.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["rank", "phase", "category_id", "category_name", "current", "target", "priority_score", "owner"])
        for i, c in enumerate(roadmap, 1):
            w.writerow([i, c["phase"], c["category_id"], c["category_name"], c["current"], c["target"], c["priority_score"], c["owner"]])

    print(f"[+] {len(cats)} CSF categories, {len(roadmap)} gaps, {len(risks)} risks")
    for f, s in fn_summary.items():
        print(f"    {f:<9} current {s['current']:<4} target {s['target']}")
    print(f"    Top 90-day items: {', '.join(c['category_id'] for c in roadmap[:5])}")
    print(f"    Risks exceeding appetite after treatment: "
          f"{', '.join(r['risk_id'] for r in risks if not r['within_appetite']) or 'none'}")
    print(f"[+] Reports written to {a.out}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
