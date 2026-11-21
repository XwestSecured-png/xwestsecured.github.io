#!/usr/bin/env python3
"""
Static malware triage: answers "what is this file and should I worry?" WITHOUT running it.

  * hashes (MD5, SHA-1, SHA-256) for lookups and IOC sharing
  * file type from magic bytes (not the extension), and extension mismatch
  * Shannon entropy, whole file and per PE section (packing / encryption)
  * PE header parsing with the standard library: machine, compile time, sections, imports,
    suspicious API combinations (injection, keylogging, anti-debug, download-and-run)
  * strings (ASCII + UTF-16LE) and IOC extraction: URLs, IPs, domains, emails, registry run keys
  * script analysis: PowerShell -EncodedCommand decoding, download cradles, obfuscation markers
  * optional YARA scan, then a scored verdict with reasons

    python3 triage/static_triage.py <file> [<file> ...] [--yara yara/rules.yar] [--out reports/]

Never execute samples. Work in an isolated VM, and keep samples in password-protected archives.
Author: Xiome West | License: MIT
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import re
import struct
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

MAGIC = [(b"MZ", "pe"), (b"\x7fELF", "elf"), (b"%PDF", "pdf"), (b"PK\x03\x04", "zip/office"), (b"\xd0\xcf\x11\xe0", "ole/office97"),
         (b"#!", "script"), (b"{\\rtf", "rtf")]
EXPECTED_EXT = {"pe": {".exe", ".dll", ".sys", ".scr", ".cpl"}, "pdf": {".pdf"}, "zip/office": {".zip", ".docx", ".xlsx", ".pptx", ".jar"},
                "ole/office97": {".doc", ".xls", ".ppt", ".msi"}}
SUSPICIOUS_APIS = {
    "process_injection": {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext"},
    "keylogging": {"SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState"},
    "anti_debug": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugStringA"},
    "download_execute": {"URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenUrlA", "WinExec", "ShellExecuteA"},
    "credential_access": {"CredEnumerateA", "CredEnumerateW", "LsaRetrievePrivateData", "MiniDumpWriteDump"},
    "crypto_ransom": {"CryptEncrypt", "CryptGenKey", "BCryptEncrypt"},
}
PACKER_SECTIONS = {"UPX0", "UPX1", "UPX2", ".aspack", ".adata", "MPRESS1", "MPRESS2", ".themida", ".vmp0", ".vmp1", ".petite", "nsp0", ".packed"}
IOC = {
    "url": re.compile(r"\bhttps?://[^\s'\"<>)\]]{4,200}", re.I),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|top|xyz|info|biz|example|onion|zip|me|cc)\b", re.I),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b"),
    "registry_run": re.compile(r"(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s'\"]*\\(?:Run|RunOnce|Winlogon|Services)\b[^\s'\"]*", re.I),
}
NOISE_DOMAINS = {"microsoft.com", "w3.org", "openssl.org", "python.org", "verisign.com", "digicert.com", "schemas.microsoft.com"}
PS_MARKERS = [
    ("encoded_command", 3, re.compile(r"-(?:e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", re.I)),
    ("download_cradle", 4, re.compile(r"(Net\.WebClient|DownloadString|DownloadFile|Invoke-WebRequest|iwr |Start-BitsTransfer)", re.I)),
    ("invoke_expression", 3, re.compile(r"\b(IEX|Invoke-Expression)\b|\|\s*iex\b", re.I)),
    ("hidden_window", 2, re.compile(r"-w(indowstyle)?\s+hidden|-nop\b|-noni\b|-ExecutionPolicy\s+Bypass", re.I)),
    ("amsi_bypass", 5, re.compile(r"AmsiUtils|amsiInitFailed|AmsiScanBuffer", re.I)),
    ("string_obfuscation", 2, re.compile(r"(\[char\]\s*\d+\s*\+\s*){3,}|-join\s*\(|-replace\s*'[^']*'\s*,\s*''|\"\s*\+\s*\"[^\"]{1,3}\"\s*\+", re.I)),
    ("defender_tamper", 5, re.compile(r"Set-MpPreference\s+-Disable|Add-MpPreference\s+-ExclusionPath", re.I)),
    # VBA / VBScript macro markers
    ("macro_autoexec", 3, re.compile(r"\b(AutoOpen|Document_Open|Workbook_Open|Auto_Open)\b", re.I)),
    ("macro_download", 4, re.compile(r"URLDownloadToFile|MSXML2\.XMLHTTP|WinHttp\.WinHttpRequest", re.I)),
    ("macro_exec", 3, re.compile(r"WScript\.Shell|\bShell\s*\(", re.I)),
]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def file_type(data: bytes) -> str:
    for sig, name in MAGIC:
        if data.startswith(sig):
            return name
    try:
        data[:4096].decode("utf-8")
        return "text"
    except UnicodeDecodeError:
        return "data"


def parse_pe(data: bytes) -> dict:
    """Minimal PE32/PE32+ parser: headers, sections, imported DLLs and functions."""
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ValueError("no PE signature")
    machine, nsec, tstamp, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    pe32plus = magic == 0x20B
    subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    dd = opt + (112 if pe32plus else 96)
    imp_rva, _ = struct.unpack_from("<II", data, dd + 8)
    sec_off = opt + opt_size
    sections = []
    for i in range(nsec):
        o = sec_off + 40 * i
        name = data[o:o + 8].rstrip(b"\0").decode("latin-1")
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, o + 8)
        ch = struct.unpack_from("<I", data, o + 36)[0]
        raw = data[rptr:rptr + rsize]
        sections.append({"name": name, "vaddr": vaddr, "vsize": vsize, "raw_size": rsize, "raw_ptr": rptr,
                         "entropy": round(entropy(raw), 2), "exec": bool(ch & 0x20000000), "write": bool(ch & 0x80000000)})

    def rva2off(rva):
        for s in sections:
            if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["raw_size"]):
                return rva - s["vaddr"] + s["raw_ptr"]
        return None

    def cstr(off):
        end = data.find(b"\0", off)
        return data[off:end].decode("latin-1") if off is not None and end > off else ""

    imports = {}
    off = rva2off(imp_rva) if imp_rva else None
    while off is not None and off + 20 <= len(data):
        oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", data, off)
        if not (oft or name_rva or ft):
            break
        dll = cstr(rva2off(name_rva)).lower(); funcs = []
        t = rva2off(oft or ft); step = 8 if pe32plus else 4
        while t is not None and t + step <= len(data) and len(funcs) < 2000:
            ent = struct.unpack_from("<Q" if pe32plus else "<I", data, t)[0]
            if not ent:
                break
            if not ent >> (63 if pe32plus else 31):          # import by name (not ordinal)
                h = rva2off(ent & 0x7FFFFFFF)
                if h is not None:
                    funcs.append(cstr(h + 2))
            t += step
        imports[dll] = funcs; off += 20
    return {"machine": {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64"}.get(machine, hex(machine)),
            "format": "PE32+" if pe32plus else "PE32", "dll": bool(chars & 0x2000),
            "subsystem": {2: "GUI", 3: "console"}.get(subsystem, subsystem),
            "compile_time": datetime.fromtimestamp(tstamp, timezone.utc).isoformat() if tstamp else None,
            "sections": sections, "imports": imports}


def strings(data: bytes, n: int = 5) -> list[str]:
    a = [m.decode() for m in re.findall(rb"[\x20-\x7e]{%d,}" % n, data)]
    u = [m.decode("utf-16le") for m in re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % n, data)]
    return a + u


def iocs(strs: list[str]) -> dict:
    blob = "\n".join(strs); out = {}
    for k, rx in IOC.items():
        vals = sorted(set(rx.findall(blob)))
        if k == "domain":
            # drop .NET/PowerShell namespaces (System.Net, Microsoft.Win32.Registry...) that look like domains
            vals = [v for v in vals if v.lower() not in NOISE_DOMAINS and not re.fullmatch(r"[\d.]+", v)
                    and not re.match(r"(System|Microsoft|Windows|Newtonsoft|Management)\.", v)]
        if k == "ipv4":
            # drop version-number look-alikes such as 1.1.0.14 (every octet small)
            vals = [v for v in vals if not v.startswith(("0.", "255.", "127.")) and max(map(int, v.split("."))) > 20]
        if vals:
            out[k] = vals[:50]
    return out


def analyze_script(text: str) -> dict:
    hits = [(n, w) for n, w, rx in PS_MARKERS if rx.search(text)]
    decoded = []
    for m in re.finditer(r"-(?:e|en|enc|encodedcommand)\s+([A-Za-z0-9+/=]{20,})", text, re.I):
        try:
            decoded.append(base64.b64decode(m.group(1)).decode("utf-16le"))
        except Exception:
            pass
    for d in decoded:                       # analyze what the decoded layer does, too
        hits += [(f"decoded:{n}", w) for n, w, rx in PS_MARKERS if rx.search(d)]
    return {"markers": [n for n, _ in hits], "score": sum(w for _, w in hits), "decoded_layers": decoded}


def triage(path: Path, yara_rules=None) -> dict:
    data = path.read_bytes()
    ft = file_type(data)
    r = {"file": path.name, "size": len(data), "type": ft, "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
         "sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(), "sha256": hashlib.sha256(data).hexdigest(),
         "entropy": round(entropy(data), 3), "reasons": [], "score": 0}

    def flag(points, why):
        r["score"] += points; r["reasons"].append(f"+{points} {why}")

    if ft in EXPECTED_EXT and path.suffix.lower() not in EXPECTED_EXT[ft]:
        flag(3, f"extension '{path.suffix}' does not match real type '{ft}'")
    if ft == "pe":
        try:
            pe = parse_pe(data); r["pe"] = pe
            names = {s["name"] for s in pe["sections"]}
            if names & PACKER_SECTIONS:
                flag(3, f"packer section names: {sorted(names & PACKER_SECTIONS)}")
            for s in pe["sections"]:
                if s["entropy"] > 7.2 and s["raw_size"] > 1024:
                    flag(2, f"high-entropy section {s['name']} ({s['entropy']}): packed or encrypted code/data")
                if s["exec"] and s["write"]:
                    flag(2, f"section {s['name']} is both writable and executable")
            funcs = {f for fs in pe["imports"].values() for f in fs}
            if 0 < len(funcs) < 10:
                flag(2, f"very few imports ({len(funcs)}): typical of packed loaders")
            for cat, apis in SUSPICIOUS_APIS.items():
                found = funcs & apis
                if len(found) >= 2 or (cat == "credential_access" and found):
                    flag(3, f"{cat.replace('_', ' ')} APIs: {sorted(found)}")
            r["imports_summary"] = {d: len(f) for d, f in pe["imports"].items()}
        except (ValueError, struct.error) as e:
            flag(2, f"malformed PE header ({e})")
    strs = strings(data)
    r["iocs"] = iocs(strs)
    if ft in ("text", "script"):
        s = analyze_script(data.decode("utf-8", "replace"))
        r["script"] = s
        if s["score"]:
            flag(min(s["score"], 12), f"script markers: {s['markers']}")
        for d in s["decoded_layers"]:
            extra = iocs([d])
            for k, v in extra.items():
                r["iocs"].setdefault(k, []); r["iocs"][k] = sorted(set(r["iocs"][k]) | set(v))
    elif r["entropy"] > 7.5 and ft == "data":
        flag(5, f"whole-file entropy {r['entropy']}: encrypted or compressed payload with no known header")
    if "registry_run" in r["iocs"]:
        flag(2, "references autorun registry keys (persistence)")
    if yara_rules is not None:
        matches = yara_rules.match(data=data, timeout=60)
        r["yara"] = [m.rule for m in matches]
        for m in matches:
            pts = {"critical": 8, "high": 5, "medium": 2}.get(m.meta.get("severity", "medium"), 2)
            flag(pts, f"YARA {m.rule} ({m.meta.get('description', '')})")
    r["verdict"] = "malicious" if r["score"] >= 10 else "suspicious" if r["score"] >= 5 else "no strong indicators"
    if "EICAR_Test_File" in r.get("yara", []):
        r["verdict"] = "EICAR test file (harmless by design)"
    return r


def report_md(results: list[dict]) -> str:
    L = ["# Static Triage Report", "", "Samples were analysed statically and never executed.", "",
         "| File | Type | Size | Entropy | Score | Verdict | SHA-256 |", "|---|---|---|---|---|---|---|"]
    L += [f"| `{r['file']}` | {r['type']} | {r['size']:,} | {r['entropy']} | {r['score']} | **{r['verdict']}** | `{r['sha256'][:16]}…` |" for r in results]
    for r in results:
        L += ["", f"## {r['file']}", "", f"- **MD5** `{r['md5']}`  ·  **SHA-1** `{r['sha1']}`", f"- **SHA-256** `{r['sha256']}`"]
        if "pe" in r:
            pe = r["pe"]
            L += [f"- **PE:** {pe['format']} {pe['machine']} {pe['subsystem']}, compiled {pe['compile_time']}",
                  "", "| Section | Raw size | Entropy | Exec | Write |", "|---|---|---|---|---|"]
            L += [f"| `{s['name']}` | {s['raw_size']:,} | {s['entropy']} | {'✓' if s['exec'] else ''} | {'✓' if s['write'] else ''} |" for s in pe["sections"]]
            L += ["", "**Imports:** " + ", ".join(f"{d} ({n})" for d, n in r["imports_summary"].items())]
        if r.get("script", {}).get("decoded_layers"):
            L += ["", "**Decoded PowerShell layer:**", "", "```powershell", *r["script"]["decoded_layers"], "```"]
        if r["iocs"]:
            L += ["", "**Extracted IOCs:**", ""] + [f"- {k}: " + ", ".join(f"`{v}`" for v in vs[:8]) for k, vs in r["iocs"].items()]
        if r.get("yara"):
            L += ["", "**YARA:** " + ", ".join(r["yara"])]
        L += ["", "**Why this verdict:**", ""] + ([f"- {x}" for x in r["reasons"]] or ["- No indicators triggered"])
    return "\n".join(L) + "\n"


def expand(paths: list[Path], max_bytes: int, log=print) -> list[Path]:
    """Expand directories recursively; skip symlinks, special files and oversized files."""
    out = []
    for p in paths:
        cands = sorted(x for x in p.rglob("*")) if p.is_dir() else [p]
        for c in cands:
            if c.is_symlink() or not c.is_file():
                continue
            if c.stat().st_size > max_bytes:
                log(f"skip (larger than limit): {c}")
                continue
            out.append(c)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Static file triage (never executes samples)")
    ap.add_argument("files", nargs="+", type=Path, help="files or directories (recursed)")
    ap.add_argument("--yara", type=Path, help="YARA rules file (requires yara-python); 'default' = bundled rules")
    ap.add_argument("--max-size-mb", type=int, default=100, help="skip files larger than this (default 100)")
    ap.add_argument("--out", type=Path)
    a = ap.parse_args(argv)
    rules = None
    if a.yara:
        try:
            import yara
        except ImportError:
            raise SystemExit("--yara needs yara-python: pip install 'westguard[yara]'")
        path = a.yara
        if str(a.yara) == "default":
            from importlib import resources
            path = Path(str(resources.files("westguard").joinpath("data", "yara", "rules.yar")))
        rules = yara.compile(filepath=str(path))
    for f in a.files:
        if not f.exists():
            raise FileNotFoundError(f)
    results = []
    for p in expand(a.files, a.max_size_mb * 1024 * 1024):
        try:
            results.append(triage(p, rules))
        except (OSError, struct.error, ValueError) as e:
            print(f"error reading {p}: {e}")
    for r in results:
        print(f"{r['file']:<32} {r['type']:<8} H={r['entropy']:<6} score={r['score']:<3} {r['verdict']}")
        for why in r["reasons"]:
            print(f"    {why}")
    if a.out:
        a.out.mkdir(parents=True, exist_ok=True)
        (a.out / "triage_report.json").write_text(json.dumps(results, indent=2, default=str))
        (a.out / "triage_report.md").write_text(report_md(results))
    verdicts = {r["verdict"] for r in results}
    return 2 if "malicious" in verdicts else 1 if "suspicious" in verdicts else 0


if __name__ == "__main__":
    main()
