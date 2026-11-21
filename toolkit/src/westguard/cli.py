"""
westguard command-line interface.

    westguard <command> [options]        run one tool (options are passed to that tool)
    westguard <command> --help           tool-specific help
    westguard list                       all commands
    westguard demo --out DIR             run every tool on bundled sample data
    westguard collectors --out DIR       export the read-only evidence collectors
    westguard doctor                     check optional dependencies and environment
    westguard web                        start the dashboard (localhost, token-protected)

Exit codes (stable, safe to use in CI and schedulers):
    0   completed, nothing at or above the tool's failure threshold
    1   completed, findings at or above the threshold (e.g. secrets found, --fail-on hit)
    2   completed, critical findings
    64  usage or input error (bad arguments, missing or unreadable file)
    70  internal error (bug); details are in the log
"""
from __future__ import annotations

import argparse
import importlib
import logging
import os
import shutil
import sys
import time
from importlib import resources
from pathlib import Path

from . import __version__

log = logging.getLogger("westguard")

EX_OK, EX_USAGE, EX_SOFTWARE = 0, 64, 70

# command -> (module, category, one-line description)
COMMANDS: dict[str, tuple[str, str, str]] = {
    "logs":         ("logtriage",    "Incident response", "Correlate Linux auth and Windows Security logs: brute force, spraying, takeover, persistence, log clearing"),
    "endpoint":     ("endpoint",     "Incident response", "Analyze endpoint triage packages (Sysmon, processes, network, persistence, ransomware impact)"),
    "file-triage":  ("filetriage",   "Incident response", "Static analysis of suspicious files: hashes, PE structure, entropy, script deobfuscation, IOCs, YARA"),
    "network":      ("netdetect",    "Detection",         "Zeek/flow analytics: port scans, beaconing, exfiltration, DNS tunneling"),
    "cloud-detect": ("clouddetect",  "Detection",         "Run 13 detections over AWS CloudTrail and Entra ID sign-in logs"),
    "sigma-export": ("sigma_export", "Detection",         "Export the cloud detections as Sigma rules for your SIEM"),
    "vuln":         ("vulnprio",     "Vulnerability mgmt", "Prioritize scanner findings with CISA KEV, EPSS, CVSS and asset context; SLA due dates"),
    "deps":         ("depcheck",     "Vulnerability mgmt", "Check an SBOM's components against OSV/PyPI/npm advisories (online or offline snapshot)"),
    "sbom":         ("sbom",         "Vulnerability mgmt", "Generate a CycloneDX 1.6 SBOM from requirements.txt / package-lock.json"),
    "secrets":      ("secrets",      "Vulnerability mgmt", "Scan a code tree for hard-coded secrets (SARIF output for code scanning)"),
    "firewall":     ("fwaudit",      "Audit",             "Audit a firewall rule set (vendor-neutral JSON) for risky rules"),
    "cloud-audit":  ("cloudaudit",   "Audit",             "34 read-only checks over AWS, Entra ID and Active Directory exports"),
    "vendor-risk":  ("vendorrisk",   "Program",           "Score third-party vendors: inherent x control strength -> tier and review cycle"),
    "kpi":          ("kpi",          "Program",           "Build a self-contained security KPI dashboard (HTML) from a metrics CSV"),
    "tabletop":     ("tabletop",     "Program",           "Score a tabletop exercise and draft the after-action report"),
    "intel":        ("intel",        "Program",           "Turn a threat-actor TTP profile into STIX 2.1 and a detection coverage matrix"),
}


def data_path(*parts: str) -> Path:
    """Path to bundled package data (works from a wheel, sdist or source checkout)."""
    return Path(str(resources.files("westguard").joinpath("data", *parts)))


def setup_logging(level: str, log_file: str | None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), handlers=handlers,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def run_tool(command: str, argv: list[str]) -> int:
    """Run one tool and normalize its result to the documented exit codes."""
    module_name = COMMANDS[command][0]
    mod = importlib.import_module(f"westguard.tools.{module_name}")
    saved = sys.argv[0]
    sys.argv[0] = f"westguard {command}"          # so tool --help shows the right usage line
    start = time.monotonic()
    try:
        result = mod.main(argv)
    except SystemExit as e:                        # argparse errors and explicit refusals
        if e.code in (0, None):
            return EX_OK
        if isinstance(e.code, str):
            log.error("%s: %s", command, e.code)
        return EX_USAGE
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        log.error("%s: cannot read input: %s", command, e)
        return EX_USAGE
    except (ValueError, KeyError, UnicodeDecodeError) as e:
        log.error("%s: input could not be parsed (%s: %s). Check the file format in the docs.", command, type(e).__name__, e)
        log.debug("traceback", exc_info=True)
        return EX_USAGE
    except Exception:                              # noqa: BLE001 - last-resort guard
        log.exception("%s: internal error", command)
        return EX_SOFTWARE
    finally:
        sys.argv[0] = saved
    log.info("%s finished in %.2fs", command, time.monotonic() - start)
    return result if isinstance(result, int) and not isinstance(result, bool) and result in (0, 1, 2) else EX_OK


def cmd_list() -> int:
    by_cat: dict[str, list[str]] = {}
    for name, (_, cat, _) in COMMANDS.items():
        by_cat.setdefault(cat, []).append(name)
    for cat, names in by_cat.items():
        print(f"\n{cat}")
        for n in names:
            print(f"  {n:<14} {COMMANDS[n][2]}")
    print("\nUtilities\n  list, demo, collectors, doctor, web, version\n")
    return EX_OK


def cmd_doctor() -> int:
    print(f"westguard {__version__} on Python {sys.version.split()[0]} ({sys.platform})")
    ok = sys.version_info >= (3, 9)
    print(f"  [{'ok' if ok else 'FAIL'}] Python >= 3.9")
    for mod, purpose in [("yara", "YARA scanning in file-triage (pip install 'westguard[yara]')"),
                         ("sigma", "Sigma validation/conversion (pip install 'westguard[sigma]')"),
                         ("stix2", "STIX 2.1 validation of intel output (pip install 'westguard[stix]')")]:
        try:
            importlib.import_module(mod)
            print(f"  [ok]   {mod:<6} {purpose}")
        except ImportError:
            print(f"  [--]   {mod:<6} not installed (optional): {purpose}")
    print(f"  [ok]   bundled data at {data_path()}" if data_path("yara", "rules.yar").exists() else "  [FAIL] bundled data missing")
    return EX_OK if ok else 1


def cmd_collectors(out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    src = data_path("collectors")
    for f in sorted(src.iterdir()):
        shutil.copy2(f, out / f.name)
        print(f"  {out / f.name}")
    print("Collectors are read-only. Review each script and get written authorization before running it on a system.")
    return EX_OK


def cmd_demo(out: Path) -> int:
    """Run every engine on the bundled synthetic data. Doubles as a post-install smoke test."""
    s = lambda *p: str(data_path("samples", *p))  # noqa: E731
    t = lambda *p: str(data_path("templates", *p))  # noqa: E731
    o = lambda name: str(out / name)  # noqa: E731
    plan = [
        ("logs", ["--linux", s("logs", "auth.log"), "--windows", s("logs", "windows_security.csv"), "--out", o("logs")]),
        ("endpoint", [s("endpoint", "WS-0102"), s("endpoint", "FS01"), "--out", o("endpoint")]),
        ("network", ["--conn", s("network", "conn.log"), "--dns", s("network", "dns.log"), "--out", o("network")]),
        ("cloud-detect", ["--cloudtrail", s("cloudlogs", "cloudtrail.jsonl"), "--signin", s("cloudlogs", "entra_signins.jsonl"), "--out", o("cloud-detect")]),
        ("sigma-export", ["--out", o("sigma")]),
        ("vuln", ["--findings", s("vuln", "scan_findings.csv"), "--assets", s("vuln", "assets.csv"), "--kev", s("vuln", "kev_sample.json"),
                  "--epss", s("vuln", "epss_sample.csv"), "--as-of", "2026-11-21", "--out", o("vuln")]),
        ("sbom", [s("app"), "--out", o("sbom.cdx.json")]),
        ("deps", [o("sbom.cdx.json"), "--osv", s("supplychain", "vuln_db_snapshot.json"), "--out", o("deps.json")]),
        ("secrets", [s("app"), "--json", o("secrets.json"), "--sarif", o("secrets.sarif")]),
        ("firewall", [s("firewall", "sample_ruleset.json"), "--out", o("firewall")]),
        ("cloud-audit", ["--aws", s("cloudaudit", "aws"), "--entra", s("cloudaudit", "entra"), "--ad", s("cloudaudit", "ad"),
                         "--as-of", "2026-11-21", "--out", o("cloud-audit")]),
        ("vendor-risk", [t("vendors_example.json"), "--as-of", "2026-11-21", "--out", o("vendor-risk")]),
        ("kpi", [s("program", "metrics.csv"), t("targets.json"), "--out", o("kpi/security_kpi_dashboard.html")]),
        ("tabletop", [t("ransomware_exercise.json"), s("program", "sample_responses.json"), "--out", o("tabletop")]),
        ("intel", [t("scattered_spider_ttps.json"), "--out", o("intel")]),
    ]
    out.mkdir(parents=True, exist_ok=True)
    results = []
    for cmd, argv in plan:
        code = run_tool(cmd, argv)
        results.append((cmd, code))
    print("\nDemo summary (exit 1/2 = findings, expected on sample data):")
    for cmd, code in results:
        print(f"  {cmd:<14} exit {code}")
    return EX_SOFTWARE if any(c >= EX_USAGE for _, c in results) else EX_OK


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    ap = argparse.ArgumentParser(prog="westguard", description="Read-only security operations toolkit.",
                                 epilog="Run 'westguard list' for all commands, 'westguard <command> --help' for options.")
    ap.add_argument("--log-level", default=os.environ.get("WESTGUARD_LOG_LEVEL", "WARNING"),
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    ap.add_argument("--log-file", default=os.environ.get("WESTGUARD_LOG_FILE"))
    ap.add_argument("--version", action="version", version=f"westguard {__version__}")
    ap.add_argument("command", nargs="?", help="command to run")
    ap.add_argument("args", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)
    ns = ap.parse_args(argv)
    setup_logging(ns.log_level, ns.log_file)

    if ns.command in (None, "help"):
        ap.print_help(); cmd_list(); return EX_OK
    if ns.command == "list":
        return cmd_list()
    if ns.command == "version":
        print(__version__); return EX_OK
    if ns.command == "doctor":
        return cmd_doctor()
    if ns.command in ("demo", "collectors"):
        sub = argparse.ArgumentParser(prog=f"westguard {ns.command}")
        sub.add_argument("--out", type=Path, required=True)
        a = sub.parse_args(ns.args)
        return cmd_demo(a.out) if ns.command == "demo" else cmd_collectors(a.out)
    if ns.command == "web":
        from .web.app import main as web_main
        return web_main(ns.args)
    if ns.command not in COMMANDS:
        log.error("unknown command '%s'. Run 'westguard list'.", ns.command)
        return EX_USAGE
    return run_tool(ns.command, ns.args)


if __name__ == "__main__":
    raise SystemExit(main())
