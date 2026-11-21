#!/usr/bin/env python3
"""
Build a self-contained security KPI dashboard (one HTML file, inline SVG, no external
requests) from a monthly metrics CSV and a targets file. Each KPI gets a status
(on target / watch / off target) with icon + label, a 12-month trend with hover values,
and a table view for accessibility.

    python3 kpi/build_dashboard.py kpi/metrics.csv kpi/targets.json --out reports/security_kpi_dashboard.html
Author: Xiome West | License: MIT
"""
from __future__ import annotations

import argparse
import csv
import html
import json
from pathlib import Path

STATUS = {"good": ("On target", "✓"), "warning": ("Watch", "!"), "critical": ("Off target", "✕")}


def status(v: float, t: dict) -> str:
    if t["better"] == "higher":
        return "good" if v >= t["target"] else "warning" if v >= t["amber"] else "critical"
    return "good" if v <= t["target"] else "warning" if v <= t["amber"] else "critical"


def sparkline(months, vals, t, w=260, h=64, pad=6):
    lo, hi = min(vals + [t["target"]]), max(vals + [t["target"]])
    span = (hi - lo) or 1
    x = lambda i: pad + i * (w - 2 * pad) / (len(vals) - 1)              # noqa: E731
    y = lambda v: h - pad - (v - lo) / span * (h - 2 * pad)              # noqa: E731
    pts = " ".join(f"{x(i):.1f},{y(v):.1f}" for i, v in enumerate(vals))
    ty = y(t["target"])
    hits = "".join(f'<rect class="hit" x="{x(i) - (w / len(vals)) / 2:.1f}" y="0" width="{w / len(vals):.1f}" height="{h}" '
                   f'data-m="{m}" data-v="{v:g}{t["unit"]}" data-cx="{x(i):.1f}" data-cy="{y(v):.1f}"/>' for i, (m, v) in enumerate(zip(months, vals)))
    return (f'<svg viewBox="0 0 {w} {h}" class="spark" role="img" aria-label="{html.escape(t["label"])} trend, '
            f'{vals[0]:g} to {vals[-1]:g}{t["unit"]} over {len(vals)} months">'
            f'<line x1="{pad}" x2="{w - pad}" y1="{ty:.1f}" y2="{ty:.1f}" class="target"/>'
            f'<polyline points="{pts}" class="line"/>'
            f'<circle cx="{x(len(vals) - 1):.1f}" cy="{y(vals[-1]):.1f}" r="4" class="end"/>'
            f'<circle r="4" class="dot" cx="0" cy="0" visibility="hidden"/>{hits}</svg>')


def build(rows, targets) -> tuple[str, list]:
    months = [r["month"] for r in rows]
    cards, summary = [], []
    for key, t in targets.items():
        vals = [float(r[key]) for r in rows]
        cur, prev = vals[-1], vals[-2]
        st = status(cur, t); label, icon = STATUS[st]
        delta = cur - prev
        improving = (delta > 0) == (t["better"] == "higher") if delta else None
        arrow = "▲" if delta > 0 else "▼" if delta < 0 else "■"
        summary.append({"kpi": t["label"], "value": cur, "target": t["target"], "status": label, "csf": t["csf"]})
        cards.append(f'''<article class="card">
  <header><h3>{html.escape(t["label"])}</h3><span class="badge {st}"><span aria-hidden="true">{icon}</span> {label}</span></header>
  <div class="val">{cur:g}<small>{t["unit"]}</small></div>
  <div class="meta"><span class="{'up' if improving else 'down' if improving is False else ''}">{arrow} {abs(delta):g}{t["unit"]} vs last month</span>
  <span>Target {'≥' if t["better"] == "higher" else '≤'} {t["target"]:g}{t["unit"]} · {t["csf"]}</span></div>
  {sparkline(months, vals, t)}
</article>''')
    counts = {s: sum(1 for x in summary if x["status"] == STATUS[s][0]) for s in STATUS}
    table = "".join(f"<tr><td>{html.escape(t['label'])}</td>" + "".join(f"<td>{float(r[k]):g}</td>" for r in rows) + "</tr>"
                    for k, t in targets.items())
    page = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security KPI Dashboard</title>
<style>
:root{{--bg:#f4f4f2;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#8a8984;--rule:#e2e1dc;--series:#2a78d6;
--good:#0ca30c;--warning:#fab219;--critical:#d03b3b;--good-ink:#006300;--crit-ink:#a32020;}}
@media (prefers-color-scheme:dark){{:root:not([data-theme=light]){{--bg:#111110;--surface:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--muted:#8f8e86;--rule:#2e2e2b;--series:#3987e5;--good-ink:#5bd35b;--crit-ink:#f08080;}}}}
:root[data-theme=dark]{{--bg:#111110;--surface:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--muted:#8f8e86;--rule:#2e2e2b;--series:#3987e5;--good-ink:#5bd35b;--crit-ink:#f08080;}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}}
main{{max-width:1180px;margin:0 auto;padding:28px 16px 48px}}h1{{font-size:24px;margin:0 0 4px}}.sub{{color:var(--ink2);margin:0 0 20px}}
.summary{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px}}.summary .badge{{font-size:14px;padding:6px 12px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px}}
.card{{background:var(--surface);border:1px solid var(--rule);border-radius:12px;padding:16px;position:relative}}
.card header{{display:flex;justify-content:space-between;align-items:flex-start;gap:8px}}h3{{font-size:14px;font-weight:600;margin:0;color:var(--ink2)}}
.badge{{display:inline-flex;align-items:center;gap:5px;font-size:12px;font-weight:600;border-radius:999px;padding:3px 9px;white-space:nowrap;border:1.5px solid;color:var(--ink)}}
.badge.good{{border-color:var(--good)}}.badge.good span{{color:var(--good)}}.badge.warning{{border-color:var(--warning)}}.badge.warning span{{color:var(--warning)}}
.badge.critical{{border-color:var(--critical)}}.badge.critical span{{color:var(--critical)}}
.val{{font-size:34px;font-weight:700;margin:8px 0 2px;font-variant-numeric:tabular-nums}}.val small{{font-size:16px;color:var(--ink2);margin-left:2px}}
.meta{{display:flex;flex-direction:column;font-size:12.5px;color:var(--ink2);margin-bottom:8px}}.up{{color:var(--good-ink)}}.down{{color:var(--crit-ink)}}
.spark{{width:100%;height:64px;display:block;overflow:visible}}.line{{fill:none;stroke:var(--series);stroke-width:2;stroke-linejoin:round;stroke-linecap:round}}
.target{{stroke:var(--muted);stroke-width:1;stroke-dasharray:3 3}}.end,.dot{{fill:var(--series);stroke:var(--surface);stroke-width:2}}.hit{{fill:transparent;cursor:crosshair}}
#tip{{position:fixed;pointer-events:none;background:var(--ink);color:var(--surface);font-size:12px;padding:5px 8px;border-radius:6px;opacity:0;transition:opacity .1s;z-index:9}}
details{{margin-top:24px;background:var(--surface);border:1px solid var(--rule);border-radius:12px;padding:12px 16px}}summary{{cursor:pointer;font-weight:600}}
.tw{{overflow-x:auto}}table{{border-collapse:collapse;font-size:12.5px;margin-top:10px;font-variant-numeric:tabular-nums}}th,td{{padding:5px 8px;border-bottom:1px solid var(--rule);text-align:right;white-space:nowrap}}th:first-child,td:first-child{{text-align:left}}
.legend{{font-size:12.5px;color:var(--ink2);margin:16px 0 0}}.legend i{{display:inline-block;width:18px;border-top:1px dashed var(--muted);vertical-align:middle;margin:0 4px 0 10px}}
.legend b{{display:inline-block;width:18px;border-top:2px solid var(--series);vertical-align:middle;margin-right:4px}}
</style></head><body><main>
<h1>Security Program KPIs</h1><p class="sub">Example Org (synthetic data) · {months[0]} to {months[-1]} · mapped to NIST CSF 2.0</p>
<div class="summary">{''.join(f'<span class="badge {s}"><span aria-hidden="true">{STATUS[s][1]}</span> {counts[s]} {STATUS[s][0].lower()}</span>' for s in STATUS)}</div>
<div class="grid">{''.join(cards)}</div>
<p class="legend"><b></b>Monthly value <i></i>Target · hover a trend for monthly values</p>
<details><summary>Table view</summary><div class="tw"><table><thead><tr><th>KPI</th>{''.join(f"<th>{m}</th>" for m in months)}</tr></thead><tbody>{table}</tbody></table></div></details>
</main><div id="tip" role="tooltip"></div>
<script>
const tip=document.getElementById('tip');
document.querySelectorAll('.spark').forEach(svg=>{{const dot=svg.querySelector('.dot');
 svg.querySelectorAll('.hit').forEach(r=>{{r.addEventListener('mousemove',e=>{{dot.setAttribute('visibility','visible');dot.setAttribute('cx',r.dataset.cx);dot.setAttribute('cy',r.dataset.cy);
  tip.textContent=r.dataset.m+': '+r.dataset.v;tip.style.left=(e.clientX+12)+'px';tip.style.top=(e.clientY-30)+'px';tip.style.opacity=1;}});
  r.addEventListener('mouseleave',()=>{{tip.style.opacity=0;dot.setAttribute('visibility','hidden');}});}});}});
</script></body></html>'''
    return page, summary


def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("metrics", type=Path); ap.add_argument("targets", type=Path)
    ap.add_argument("--out", type=Path, default=Path("reports/security_kpi_dashboard.html")); a = ap.parse_args(argv)
    rows = list(csv.DictReader(a.metrics.open()))
    page, summary = build(rows, json.loads(a.targets.read_text()))
    a.out.parent.mkdir(parents=True, exist_ok=True); a.out.write_text(page)
    for s in summary:
        print(f"  {s['status']:<11} {s['kpi']:<38} {s['value']:g} (target {s['target']:g})  {s['csf']}")
    return summary


if __name__ == "__main__":
    main()
