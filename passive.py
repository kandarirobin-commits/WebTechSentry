"""
WebTechSentry - Phase 1: Passive reconnaissance & OSINT.

Nothing in this module sends traffic to the target's web server.
  * WHOIS        -> registry / registrar WHOIS servers (via the `whois` CLI)
  * DNS          -> your configured recursive resolver (dnspython, or `dig`)
  * Subdomains   -> crt.sh Certificate Transparency search
  * OSINT        -> archived copies of the site on the Wayback Machine
"""

import json
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "WebTechSentry/2.0 (authorized recon)"
DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

# Minimal list of common two-level public suffixes (no external dependency).
_SECOND_LEVEL = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "co.jp", "com.br",
    "com.cn", "co.nz", "co.za", "com.mx", "com.sg", "com.tr",
}

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def is_ip(host: str) -> bool:
    return bool(_IPV4.match(host)) or ":" in host


def registrable_domain(host: str) -> str:
    """Best-effort registrable domain (example.co.uk, example.com)."""
    host = host.lower().strip(".")
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _http_get(url: str, timeout: int = 30, max_bytes: int = 1_000_000) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read(max_bytes).decode("utf-8", errors="replace")


# --------------------------------------------------------------------------
# WHOIS
# --------------------------------------------------------------------------

_WHOIS_KEYS = {
    "registrar": ("registrar",),
    "creation_date": ("creation date", "created", "created on", "registered on"),
    "expiry_date": ("registry expiry date", "registrar registration expiration date",
                    "expiry date", "expires", "expiration date", "paid-till"),
    "updated_date": ("updated date", "last updated", "last-update", "modified"),
    "registrant_org": ("registrant organization", "registrant organisation", "org"),
    "dnssec": ("dnssec",),
}


def parse_whois(text: str) -> dict:
    fields = {k: None for k in _WHOIS_KEYS}
    fields["name_servers"] = []
    fields["status"] = []
    fields["emails"] = []
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if not value:
            continue
        for field, names in _WHOIS_KEYS.items():
            if key in names and not fields[field]:
                fields[field] = value
        if key in ("name server", "nserver"):
            ns = value.split()[0].lower().rstrip(".")
            if ns not in fields["name_servers"]:
                fields["name_servers"].append(ns)
        elif key in ("domain status", "status"):
            st = value.split()[0]
            if st not in fields["status"]:
                fields["status"].append(st)
    for email in re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", text):
        if email.lower() not in fields["emails"]:
            fields["emails"].append(email.lower())
    return fields


def whois_lookup(domain: str, timeout: int = 30) -> dict:
    if shutil.which("whois"):
        proc = subprocess.run(["whois", domain], capture_output=True, text=True,
                              timeout=timeout, check=False)
        raw = proc.stdout
    else:
        try:
            import whois as pywhois  # python-whois, optional
        except ImportError:
            raise RuntimeError("WHOIS needs the `whois` command (sudo apt install whois) "
                               "or the python-whois package.")
        raw = str(pywhois.whois(domain))
    return {"domain": domain, "fields": parse_whois(raw), "raw": raw}


# --------------------------------------------------------------------------
# DNS + email security
# --------------------------------------------------------------------------

def _query(name: str, rtype: str, timeout: int = 5):
    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        dns = None

    if dns is not None:
        try:
            answers = dns.resolver.resolve(name, rtype, lifetime=timeout)
            return [r.to_text().strip('"') for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except dns.exception.Timeout:
            return []
    if shutil.which("dig"):
        out = subprocess.run(["dig", "+short", "+time=3", "+tries=1", name, rtype],
                             capture_output=True, text=True, timeout=timeout + 5, check=False)
        return [ln.strip().strip('"') for ln in out.stdout.splitlines() if ln.strip()]
    raise RuntimeError("DNS needs dnspython (pip install dnspython) or the `dig` command.")


def analyze_email_security(txt_records, dmarc_records) -> dict:
    spf = next((r for r in txt_records if r.lower().startswith("v=spf1")), None)
    dmarc = next((r for r in dmarc_records if r.lower().startswith("v=dmarc1")), None)
    notes = []
    if not spf:
        notes.append(("high", "No SPF record found - domain can be spoofed more easily."))
    else:
        if re.search(r"[\s]\+all\b", spf):
            notes.append(("high", "SPF ends with +all - allows any sender."))
        elif re.search(r"[\s]\?all\b", spf):
            notes.append(("medium", "SPF uses ?all (neutral) - no enforcement."))
        elif re.search(r"[\s]~all\b", spf):
            notes.append(("low", "SPF uses ~all (soft fail)."))
        elif re.search(r"[\s]-all\b", spf):
            notes.append(("ok", "SPF uses -all (hard fail)."))
    if not dmarc:
        notes.append(("high", "No DMARC record at _dmarc - no policy for spoofed mail."))
    else:
        m = re.search(r"\bp=(\w+)", dmarc, re.I)
        policy = m.group(1).lower() if m else "unknown"
        sev = {"none": "medium", "quarantine": "low", "reject": "ok"}.get(policy, "info")
        notes.append((sev, f"DMARC policy is p={policy}."))
    return {"spf": spf, "dmarc": dmarc, "notes": notes}


def dns_lookup(domain: str) -> dict:
    records = {}
    for rtype in DNS_TYPES:
        records[rtype] = _query(domain, rtype)
    www = _query("www." + domain, "CNAME")
    if www:
        records["CNAME"] = records["CNAME"] + [f"www -> {v}" for v in www]
    dmarc = _query("_dmarc." + domain, "TXT")
    return {
        "domain": domain,
        "records": records,
        "email_security": analyze_email_security(records.get("TXT", []), dmarc),
    }


# --------------------------------------------------------------------------
# Subdomains via crt.sh
# --------------------------------------------------------------------------

def crtsh_subdomains(domain: str, timeout: int = 45) -> dict:
    url = "https://crt.sh/?q=" + urllib.parse.quote("%." + domain) + "&output=json"
    last_err = None
    body = None
    for _ in range(2):  # crt.sh is flaky; one retry
        try:
            body = _http_get(url, timeout=timeout, max_bytes=20_000_000)
            break
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_err = exc
    if body is None:
        raise RuntimeError(f"crt.sh request failed: {last_err}")
    try:
        entries = json.loads(body) if body.strip() else []
    except json.JSONDecodeError:
        raise RuntimeError("crt.sh returned a non-JSON response (it may be rate-limiting).")

    names = set()
    for entry in entries:
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.")
            if name == domain or name.endswith("." + domain):
                names.add(name)
    subs = sorted(names)
    return {"source": "crt.sh", "domain": domain, "count": len(subs), "subdomains": subs}


# --------------------------------------------------------------------------
# OSINT harvesting from archived pages (Wayback Machine)
# --------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(?<![\w/.-])\+?\(?\d[\d\s().-]{7,18}\d(?![\w-])")
_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_ASSET_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js")


def extract_indicators(text: str, domain: str) -> dict:
    emails = {e.lower() for e in _EMAIL_RE.findall(text) if not e.lower().endswith(_ASSET_EXT)}
    phones = set()
    for m in _PHONE_RE.findall(text):
        digits = re.sub(r"\D", "", m)
        has_format = m.startswith("+") or "(" in m or re.search(r"\d[\s.-]\d", m)
        if 8 <= len(digits) <= 15 and has_format and not re.match(r"^(19|20)\d{2}[-.]\d{2}", m):
            phones.add(" ".join(m.split()))
    host_re = re.compile(r"\b(?:[a-z0-9-]+\.)+" + re.escape(domain) + r"\b", re.I)
    hosts = {h.lower() for h in host_re.findall(text)}
    ips = {ip for ip in _IP_RE.findall(text) if not ip.startswith(("0.", "255."))}
    return {"emails": emails, "phones": phones, "hostnames": hosts, "ips": ips}


def osint_harvest(domain: str, max_pages: int = 4) -> dict:
    out = {"emails": set(), "phones": set(), "hostnames": set(), "ips": set()}
    pages, notes = [], []

    # Candidate pages: closest homepage snapshot + archived contact/about-style URLs
    candidates = []
    try:
        avail = json.loads(_http_get(
            "https://archive.org/wayback/available?url=" + urllib.parse.quote(domain), timeout=20))
        snap = (avail.get("archived_snapshots") or {}).get("closest") or {}
        if snap.get("url"):
            candidates.append(snap["url"])
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        notes.append(f"Wayback availability lookup failed: {exc}")

    try:
        cdx = json.loads(_http_get(
            "https://web.archive.org/cdx/search/cdx?url=" + urllib.parse.quote(domain + "/*")
            + "&output=json&fl=timestamp,original&filter=statuscode:200"
              "&collapse=urlkey&limit=300", timeout=30))
        for ts, original in cdx[1:]:
            for h in re.findall(r"//([^/:]+)", original):
                if h.lower().endswith(domain):
                    out["hostnames"].add(h.lower())
            if re.search(r"contact|about|team|support|imprint|privacy", original, re.I) \
                    and not original.lower().endswith(_ASSET_EXT):
                candidates.append(f"https://web.archive.org/web/{ts}/{original}")
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError) as exc:
        notes.append(f"Wayback CDX lookup failed: {exc}")

    seen = set()
    for url in candidates:
        if url in seen or len(pages) >= max_pages:
            continue
        seen.add(url)
        raw_url = re.sub(r"/web/(\d+)/", r"/web/\1id_/", url, count=1)  # un-rewritten original HTML
        try:
            text = _http_get(raw_url, timeout=30)
        except (urllib.error.URLError, TimeoutError, OSError):
            continue
        pages.append(url)
        for key, vals in extract_indicators(text, domain).items():
            out[key] |= vals

    if not pages:
        notes.append("No archived pages could be fetched; results are limited to URL hostnames.")
    notes.append("Phone numbers are regex candidates and may include false positives.")
    return {
        "domain": domain,
        "pages_analyzed": pages,
        "emails": sorted(out["emails"]),
        "phones": sorted(out["phones"]),
        "hostnames": sorted(out["hostnames"]),
        "ips": sorted(out["ips"]),
        "notes": notes,
    }
