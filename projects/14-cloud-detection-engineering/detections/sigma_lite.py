"""
A small Sigma-compatible matcher. Rules are written once as Sigma-style selections and
used two ways: evaluated here in Python (so they can be unit-tested), and exported as
real Sigma YAML for any SIEM backend (Splunk, Sentinel, Elastic) via pySigma.

Supported: dotted field paths, lists (OR), modifiers |contains |startswith |endswith |re,
conditions "sel", "sel and not filter", "sel1 or sel2", and Sigma correlation types
event_count and value_count with group-by and timespan.
"""
from __future__ import annotations

import re
from collections import defaultdict, deque
from datetime import datetime, timedelta


def get(event: dict, path: str):
    cur = event
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _match_value(actual, expected, mod: str | None) -> bool:
    if actual is None:
        return expected is None
    a = str(actual).lower(); e = str(expected).lower()
    if mod == "contains": return e in a
    if mod == "startswith": return a.startswith(e)
    if mod == "endswith": return a.endswith(e)
    if mod == "re": return re.search(str(expected), str(actual)) is not None
    return a == e


def match_selection(event: dict, sel: dict) -> bool:
    for key, exp in sel.items():                      # AND across fields
        field, _, mod = key.partition("|")
        vals = exp if isinstance(exp, list) else [exp]
        if not any(_match_value(get(event, field), v, mod or None) for v in vals):  # OR within field
            return False
    return True


def match_detection(event: dict, detection: dict) -> bool:
    cond = detection["condition"]
    named = {k: v for k, v in detection.items() if k != "condition"}
    expr = cond
    for name in sorted(named, key=len, reverse=True):
        expr = re.sub(rf"\b{name}\b", "True" if match_selection(event, named[name]) else "False", expr)
    if not re.fullmatch(r"[\sA-Za-z()]*", expr) or set(re.findall(r"[A-Za-z]+", expr)) - {"True", "False", "and", "or", "not"}:
        raise ValueError(f"unsupported condition: {cond}")
    return eval(expr, {"__builtins__": {}}, {})       # tokens verified above: only True/False/and/or/not/()


def ts(event: dict, field: str) -> datetime:
    return datetime.fromisoformat(str(get(event, field)).replace("Z", "+00:00"))


def correlate(events: list[dict], detection: dict, corr: dict, time_field: str) -> list[dict]:
    """Sliding-window event_count / value_count. Returns one hit per group per burst."""
    span = timedelta(seconds=corr["timespan_s"])
    windows, hits, open_hit = defaultdict(deque), [], {}
    for e in sorted((e for e in events if match_detection(e, detection)), key=lambda e: ts(e, time_field)):
        key = tuple(str(get(e, g)) for g in corr["group_by"])
        t = ts(e, time_field); w = windows[key]; w.append(e)
        while w and ts(w[0], time_field) < t - span:
            w.popleft()
        n = len(w) if corr["type"] == "event_count" else len({str(get(x, corr["field"])) for x in w})
        h = open_hit.get(key)
        if h and t - ts(h["sample"], time_field) <= span:      # same burst: extend the existing alert
            h["members"].update(id(x) for x in w) if corr["type"] == "event_count" else h["values"].update(str(get(x, corr["field"])) for x in w)
            h["count"] = len(h["members"]) if corr["type"] == "event_count" else len(h["values"])
            h["last"], h["sample"] = get(e, time_field), e
        elif n >= corr["gte"]:
            h = {"group": dict(zip(corr["group_by"], key)), "count": n, "first": get(w[0], time_field), "last": get(e, time_field),
                 "sample": e, "members": {id(x) for x in w}, "values": {str(get(x, corr.get("field", ""))) for x in w}}
            open_hit[key] = h; hits.append(h)
    for h in hits:
        h.pop("members"); h.pop("values")
    return hits
