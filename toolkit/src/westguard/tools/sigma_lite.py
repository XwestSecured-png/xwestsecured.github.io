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


def _eval_bool(tokens: list[str]) -> bool:
    """Evaluate True/False/and/or/not/( ) with normal precedence. No eval()."""
    pos = 0

    def expr():
        nonlocal pos
        v = term()
        while pos < len(tokens) and tokens[pos] == "or":
            pos += 1; r = term(); v = v or r
        return v

    def term():
        nonlocal pos
        v = factor()
        while pos < len(tokens) and tokens[pos] == "and":
            pos += 1; r = factor(); v = v and r
        return v

    def factor():
        nonlocal pos
        if pos >= len(tokens):
            raise ValueError("unexpected end of condition")
        t = tokens[pos]; pos += 1
        if t == "not":
            return not factor()
        if t == "(":
            v = expr()
            if pos >= len(tokens) or tokens[pos] != ")":
                raise ValueError("unbalanced parentheses in condition")
            pos += 1
            return v
        if t in ("True", "False"):
            return t == "True"
        raise ValueError(f"unexpected token in condition: {t}")

    v = expr()
    if pos != len(tokens):
        raise ValueError("trailing tokens in condition")
    return v


def match_detection(event: dict, detection: dict) -> bool:
    named = {k: v for k, v in detection.items() if k != "condition"}
    tokens = re.findall(r"\(|\)|[A-Za-z0-9_]+", detection["condition"])
    resolved = []
    for t in tokens:
        if t in named:
            resolved.append("True" if match_selection(event, named[t]) else "False")
        elif t in ("and", "or", "not", "(", ")"):
            resolved.append(t)
        else:
            raise ValueError(f"unsupported condition: {detection['condition']}")
    return _eval_bool(resolved)


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
