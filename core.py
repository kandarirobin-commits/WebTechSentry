"""
WebTechSentry core
Shared scanning/reporting logic used by the CLI (fingerprint.py), the Tk GUI
(gui.py) and the PySide6 GUI (gui_qt.py). Keeping this in one module means all
front ends behave identically and there's only one place to fix a bug.

  scan()    - original single-purpose WhatWeb scan
  assess()  - multi-module assessment:
                Phase 1 (passive):  whois, dns, subdomains, osint
                Phase 2 (active):   tech, tls, headers, os, whatweb
"""

import csv
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_TIMEOUT = 90
DEFAULT_AGGRESSION = 1


def validate_url(value: str) -> str:
    """Reject anything that isn't a clean http(s) URL with a hostname."""
    if any(ch.isspace() for ch in value):
        raise ValueError("URL must not contain spaces.")
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a complete http:// or https:// URL.")
    return value


def whatweb_available() -> bool:
    return shutil.which("whatweb") is not None


def run_whatweb(target: str, aggression: int = DEFAULT_AGGRESSION, timeout: int = DEFAULT_TIMEOUT):
    """Run WhatWeb and return (command, stdout, stderr, return_code, timed_out)."""
    command = ["whatweb", f"--aggression={aggression}", "--log-json=-", target]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
        return command, result.stdout, result.stderr, result.returncode, False
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        stderr += f"\nScan timed out after {timeout} seconds."
        return command, stdout, stderr, None, True


def parse_whatweb_json(stdout: str):
    """Best-effort parse of WhatWeb's --log-json=- output into a list of
    {plugin, version, detail} findings. Returns [] if nothing parseable;
    the raw stdout is always preserved separately regardless."""
    findings = []
    stdout = (stdout or "").strip()
    if not stdout:
        return findings
    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            data = [data]
    except json.JSONDecodeError:
        data = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    for entry in data:
        plugins = entry.get("plugins", {}) if isinstance(entry, dict) else {}
        for name, details in plugins.items():
            version = None
            strings = []
            if isinstance(details, dict):
                version = details.get("version")
                strings = details.get("string") or []
                if isinstance(version, list):
                    version = ", ".join(str(v) for v in version)
            findings.append(
                {
                    "plugin": name,
                    "version": version,
                    "detail": ", ".join(str(s) for s in strings) if strings else None,
                }
            )
    return findings


def write_reports(out_dir: Path, record: dict, findings: list):
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = record["timestamp_utc"]
    json_path = out_dir / f"fingerprint_{stamp}.json"
    csv_path = out_dir / f"summary_{stamp}.csv"

    record_with_findings = dict(record)
    record_with_findings["findings"] = findings
    json_path.write_text(json.dumps(record_with_findings, indent=2), encoding="utf-8")

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        if findings:
            writer.writerow(["target", "timestamp_utc", "plugin", "version", "detail"])
            for f in findings:
                writer.writerow(
                    [record["target"], stamp, f["plugin"], f.get("version") or "", f.get("detail") or ""]
                )
        else:
            summary = " ".join((record["stdout"] or record["stderr"]).split())[:4000]
            writer.writerow(["target", "timestamp_utc", "return_code", "timed_out", "summary"])
            writer.writerow([record["target"], stamp, record["return_code"], record["timed_out"], summary])

    return json_path, csv_path


def scan(target: str, aggression: int = DEFAULT_AGGRESSION, timeout: int = DEFAULT_TIMEOUT, out_dir: str = "reports"):
    """Run one full validate -> scan -> parse -> report cycle.
    Returns a dict with everything a caller (CLI or GUI) needs to display."""
    target = validate_url(target)
    command, stdout, stderr, return_code, timed_out = run_whatweb(target, aggression, timeout)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    record = {
        "target": target,
        "timestamp_utc": stamp,
        "command": command,
        "return_code": return_code,
        "timed_out": timed_out,
        "stdout": stdout,
        "stderr": stderr,
        "note": "Fingerprint matches are clues, not proof. Validate important findings manually.",
    }

    findings = parse_whatweb_json(stdout)
    json_path, csv_path = write_reports(Path(out_dir), record, findings)

    return {
        "record": record,
        "findings": findings,
        "json_path": json_path,
        "csv_path": csv_path,
    }


# ===========================================================================
# Multi-module assessment (Phase 1 passive + Phase 2 fingerprinting)
# ===========================================================================

import passive
import fingerprint_tech as ft

PHASE1_MODULES = [
    ("whois", "WHOIS lookup"),
    ("dns", "DNS records + SPF/DMARC"),
    ("subdomains", "Subdomains (crt.sh)"),
    ("osint", "OSINT harvest (Wayback)"),
]
PHASE2_MODULES = [
    ("tech", "Tech stack (Wappalyzer)"),
    ("tls", "SSL/TLS certificate"),
    ("headers", "Security headers"),
    ("os", "OS discovery"),
    ("whatweb", "WhatWeb scan"),
]
ALL_MODULES = [k for k, _ in PHASE1_MODULES + PHASE2_MODULES]
MODULE_LABELS = dict(PHASE1_MODULES + PHASE2_MODULES)
PHASE1_KEYS = [k for k, _ in PHASE1_MODULES]
PHASE2_KEYS = [k for k, _ in PHASE2_MODULES if k != "whatweb"]


def assess(target, modules, aggression=DEFAULT_AGGRESSION, timeout=DEFAULT_TIMEOUT,
           out_dir="reports", use_nmap=False, progress=None):
    """Run the selected modules against one target. Each module is isolated:
    a failure is recorded in result['errors'] and the rest still run."""
    target = validate_url(target)
    parsed = urlparse(target)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    domain = None if passive.is_ip(host) else passive.registrable_domain(host)
    say = progress or (lambda msg: None)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    result = {"target": target, "host": host, "domain": domain, "timestamp_utc": stamp,
              "modules_run": [m for m in ALL_MODULES if m in modules],
              "modules": {}, "errors": {},
              "note": "Fingerprint matches are clues, not proof. Validate important findings manually."}
    cache = {}

    def page():
        if "page" not in cache:
            cache["page"] = ft.fetch_page(target)
        return cache["page"]

    def need_domain():
        if not domain:
            raise ValueError("This module needs a domain name, not an IP address.")
        return domain

    def run_whatweb_module():
        if not whatweb_available():
            raise RuntimeError("whatweb not found on PATH (sudo apt install whatweb).")
        cmd, out, err, rc, timed_out = run_whatweb(target, aggression, timeout)
        return {"command": cmd, "return_code": rc, "timed_out": timed_out,
                "findings": parse_whatweb_json(out), "stdout": out, "stderr": err}

    steps = {
        "whois": lambda: passive.whois_lookup(need_domain()),
        "dns": lambda: passive.dns_lookup(need_domain()),
        "subdomains": lambda: passive.crtsh_subdomains(need_domain()),
        "osint": lambda: passive.osint_harvest(need_domain()),
        "tech": lambda: ft.detect_technologies(target, page()),
        "tls": lambda: ft.tls_info(host, port if parsed.scheme == "https" else 443),
        "headers": lambda: ft.audit_headers(page()),
        "os": lambda: ft.os_discovery(host, use_nmap=use_nmap),
        "whatweb": run_whatweb_module,
    }
    for key in ALL_MODULES:
        if key not in modules:
            continue
        say(f"Running: {MODULE_LABELS[key]}...")
        try:
            result["modules"][key] = steps[key]()
        except Exception as exc:  # isolate module failures
            result["errors"][key] = str(exc)

    result["json_path"], result["csv_path"] = write_assessment_reports(Path(out_dir), result)
    result["json_path"], result["csv_path"] = str(result["json_path"]), str(result["csv_path"])
    say("Done.")
    return result


def flatten(result):
    """Turn a result into rows (module, item, value, detail, severity) for tables/CSV."""
    rows = []
    m = result["modules"]

    if "whois" in m:
        f = m["whois"]["fields"]
        for k in ("registrar", "creation_date", "expiry_date", "updated_date", "registrant_org", "dnssec"):
            if f.get(k):
                rows.append(("whois", k.replace("_", " ").title(), f[k], "", "info"))
        for ns in f["name_servers"]:
            rows.append(("whois", "Name server", ns, "", "info"))
        for st in f["status"]:
            rows.append(("whois", "Status", st, "", "info"))
        for em in f["emails"]:
            rows.append(("whois", "Contact email", em, "", "info"))
    if "dns" in m:
        for rtype, vals in m["dns"]["records"].items():
            for v in vals:
                rows.append(("dns", rtype, v, "", "info"))
        es = m["dns"]["email_security"]
        rows.append(("dns", "SPF", es["spf"] or "(none)", "", "info"))
        rows.append(("dns", "DMARC", es["dmarc"] or "(none)", "", "info"))
        for sev, note in es["notes"]:
            rows.append(("dns", "Email security", note, "", sev))
    if "subdomains" in m:
        for s in m["subdomains"]["subdomains"]:
            rows.append(("subdomains", "Subdomain", s, "crt.sh", "info"))
    if "osint" in m:
        o = m["osint"]
        for key, label in (("emails", "Email"), ("phones", "Phone (candidate)"),
                           ("hostnames", "Hostname"), ("ips", "IP address")):
            for v in o[key]:
                rows.append(("osint", label, v, "", "info"))
    if "tech" in m:
        for t in m["tech"]["technologies"]:
            rows.append(("tech", t["name"], ", ".join(t["versions"]), ", ".join(t["categories"]), "info"))
    if "tls" in m:
        t = m["tls"]
        for label, key in (("Protocol", "protocol"), ("Cipher", "cipher"), ("Subject", "subject"),
                           ("Issuer", "issuer"), ("Valid from", "not_before"),
                           ("Valid until", "not_after"), ("Days remaining", "days_remaining"),
                           ("Serial", "serial")):
            if t.get(key) is not None:
                rows.append(("tls", label, t[key], "", "info"))
        rows.append(("tls", "Chain verified", t["chain_verified"], t.get("verify_error") or "",
                     "ok" if t["chain_verified"] else "high"))
        for s in t["san"]:
            rows.append(("tls", "SAN", s, "", "info"))
        for n in t["notes"]:
            rows.append(("tls", "Note", n, "", "medium"))
    if "headers" in m:
        h = m["headers"]
        for c in h["checks"]:
            rows.append(("headers", c["header"], "present" if c["present"] else "MISSING",
                         c["value"] if c["present"] else c["advice"], c["severity"]))
        for d in h["disclosure"]:
            rows.append(("headers", "Info disclosure: " + d["header"], d["value"], d["advice"], "low"))
        for c in h["cookie_issues"]:
            rows.append(("headers", "Cookie: " + c["cookie"], "missing " + ", ".join(c["missing"]), "", "low"))
    if "os" in m:
        o = m["os"]
        if o["ping_ttl"] is not None:
            rows.append(("os", "Ping TTL", o["ping_ttl"],
                         f"initial {o['initial_ttl']}, ~{o['estimated_hops']} hop(s)", "info"))
            rows.append(("os", "OS guess (TTL)", o["ttl_guess"], "", "info"))
        for line in o["nmap"] or []:
            rows.append(("os", "Nmap", line, "", "info"))
        for n in o["notes"]:
            rows.append(("os", "Note", n, "", "info"))
    if "whatweb" in m:
        for f in m["whatweb"]["findings"]:
            rows.append(("whatweb", f["plugin"], f.get("version") or "", f.get("detail") or "", "info"))
    for key, err in result["errors"].items():
        rows.append((key, "ERROR", err, "", "high"))
    return rows


def summarize(result):
    """Short human-readable highlights shared by the CLI and GUI overview."""
    m, lines = result["modules"], []
    if "whois" in m:
        f = m["whois"]["fields"]
        lines.append(f"Registrar: {f.get('registrar') or 'unknown'}; expires {f.get('expiry_date') or 'unknown'}")
    if "dns" in m:
        for sev, note in m["dns"]["email_security"]["notes"]:
            lines.append(f"[{sev}] {note}")
    if "subdomains" in m:
        lines.append(f"{m['subdomains']['count']} subdomain(s) found in CT logs")
    if "osint" in m:
        o = m["osint"]
        lines.append(f"OSINT: {len(o['emails'])} email(s), {len(o['phones'])} phone candidate(s), "
                     f"{len(o['hostnames'])} hostname(s)")
    if "tech" in m:
        lines.append(f"{len(m['tech']['technologies'])} technology signal(s) ({m['tech']['engine']})")
    if "tls" in m:
        t = m["tls"]
        lines.append(f"TLS: {t['protocol']}, expires in {t['days_remaining']} day(s), {len(t['san'])} SAN(s)")
    if "headers" in m:
        missing = [c["header"] for c in m["headers"]["checks"] if not c["present"]]
        lines.append("Missing security headers: " + (", ".join(missing) if missing else "none"))
    if "os" in m and m["os"]["ttl_guess"]:
        lines.append(f"OS (TTL heuristic): {m['os']['ttl_guess']}")
    for key, err in result["errors"].items():
        lines.append(f"[error] {MODULE_LABELS.get(key, key)}: {err}")
    return lines


def write_assessment_reports(out_dir: Path, result: dict):
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = result["timestamp_utc"]
    json_path = out_dir / f"assessment_{stamp}.json"
    csv_path = out_dir / f"assessment_{stamp}.csv"
    json_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["target", "timestamp_utc", "module", "item", "value", "detail", "severity"])
        for module, item, value, detail, sev in flatten(result):
            writer.writerow([result["target"], stamp, module, item, value, detail, sev])
    return json_path, csv_path
