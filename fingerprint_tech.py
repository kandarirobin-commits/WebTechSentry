"""
WebTechSentry - Phase 2: Infrastructure & technology fingerprinting.

Unlike Phase 1, these checks DO contact the target (one HTTP GET, one TLS
handshake, one ICMP ping, optionally an Nmap OS scan). Only run them against
assets you are authorized to test.
"""

import platform
import re
import shutil
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from urllib.parse import urlparse
import urllib.error
import urllib.request

USER_AGENT = "WebTechSentry/2.0 (authorized recon)"


# --------------------------------------------------------------------------
# Single shared HTTP fetch (used by tech detection and header audit)
# --------------------------------------------------------------------------

def fetch_page(url: str, timeout: int = 20, max_bytes: int = 500_000) -> dict:
    ctx = ssl._create_unverified_context()  # cert problems are reported by tls_info()
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
    except urllib.error.HTTPError as exc:  # still has headers/body worth analyzing
        resp = exc
    except (urllib.error.URLError, OSError) as exc:
        raise RuntimeError(f"Could not fetch {url}: {exc}")
    headers = {}
    for key in resp.headers.keys():
        headers[key.lower()] = ", ".join(resp.headers.get_all(key) or [])
    return {
        "status": getattr(resp, "status", None) or resp.code,
        "final_url": resp.geturl() if hasattr(resp, "geturl") else url,
        "headers": headers,
        "cookies": resp.headers.get_all("Set-Cookie") or [],
        "html": resp.read(max_bytes).decode("utf-8", errors="replace"),
    }


# --------------------------------------------------------------------------
# Technology detection (Wappalyzer bindings with a built-in fallback)
# --------------------------------------------------------------------------

# (name, category, source, regex)   source: html | header:<name> | cookie | meta
# A single capture group, if present, is taken as the version.
SIGNATURES = [
    ("WordPress", "CMS", "html", r"/wp-(?:content|includes)/"),
    ("WordPress", "CMS", "meta", r"WordPress\s*([\d.]+)?"),
    ("Drupal", "CMS", "meta", r"Drupal\s*([\d.]+)?"),
    ("Drupal", "CMS", "header:x-generator", r"Drupal\s*([\d.]+)?"),
    ("Joomla", "CMS", "meta", r"Joomla!?\s*([\d.]+)?"),
    ("Shopify", "E-commerce", "html", r"cdn\.shopify\.com"),
    ("Wix", "CMS", "html", r"static\.wixstatic\.com"),
    ("Squarespace", "CMS", "html", r"static1?\.squarespace\.com"),
    ("Magento", "E-commerce", "cookie", r"mage-cache|frontend="),
    ("jQuery", "JavaScript library", "html", r"jquery[-.]?([\d.]+)?(?:\.min)?\.js"),
    ("React", "JavaScript framework", "html", r"data-reactroot|react(?:-dom)?(?:\.production)?\.min\.js"),
    ("Next.js", "JavaScript framework", "html", r"/_next/static/|__NEXT_DATA__"),
    ("Vue.js", "JavaScript framework", "html", r"vue(?:\.runtime)?(?:\.min)?\.js|data-v-[0-9a-f]{6,}"),
    ("Nuxt.js", "JavaScript framework", "html", r"/_nuxt/"),
    ("Angular", "JavaScript framework", "html", r"ng-version=\"([\d.]+)\"|angular(?:\.min)?\.js"),
    ("Bootstrap", "UI framework", "html", r"bootstrap(?:\.min)?\.(?:css|js)|bootstrap@([\d.]+)"),
    ("Google Analytics", "Analytics", "html", r"google-analytics\.com/(?:ga|analytics)\.js|gtag/js\?id=|googletagmanager\.com/gtag"),
    ("Google Tag Manager", "Tag manager", "html", r"googletagmanager\.com/gtm\.js"),
    ("Matomo", "Analytics", "html", r"matomo\.js|piwik\.js"),
    ("Hotjar", "Analytics", "html", r"static\.hotjar\.com"),
    ("Facebook Pixel", "Analytics", "html", r"connect\.facebook\.net/.*/fbevents\.js"),
    ("Cloudflare", "CDN", "header:server", r"cloudflare"),
    ("Cloudflare", "CDN", "header:cf-ray", r".+"),
    ("Amazon CloudFront", "CDN", "header:via", r"CloudFront"),
    ("Fastly", "CDN", "header:x-served-by", r"cache-"),
    ("Akamai", "CDN", "header:server", r"AkamaiGHost"),
    ("Nginx", "Web server", "header:server", r"nginx/?([\d.]+)?"),
    ("Apache HTTP Server", "Web server", "header:server", r"Apache/?([\d.]+)?"),
    ("Microsoft IIS", "Web server", "header:server", r"Microsoft-IIS/?([\d.]+)?"),
    ("LiteSpeed", "Web server", "header:server", r"LiteSpeed"),
    ("Caddy", "Web server", "header:server", r"Caddy"),
    ("PHP", "Programming language", "header:x-powered-by", r"PHP/?([\d.]+)?"),
    ("PHP", "Programming language", "cookie", r"PHPSESSID"),
    ("ASP.NET", "Web framework", "header:x-powered-by", r"ASP\.NET"),
    ("ASP.NET", "Web framework", "header:x-aspnet-version", r"([\d.]+)"),
    ("Express", "Web framework", "header:x-powered-by", r"Express"),
    ("Java Servlet / JSP", "Programming language", "cookie", r"JSESSIONID"),
    ("Django", "Web framework", "cookie", r"csrftoken|django"),
    ("Laravel", "Web framework", "cookie", r"laravel_session"),
    ("Ruby on Rails", "Web framework", "header:x-powered-by", r"Phusion Passenger|Rails"),
    ("MySQL (phpMyAdmin)", "Database", "html", r"phpmyadmin"),
]


def _meta_generator(html: str):
    m = re.search(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", html, re.I)
    if not m:
        m = re.search(r"<meta[^>]+content=[\"']([^\"']+)[\"'][^>]+name=[\"']generator[\"']", html, re.I)
    return m.group(1) if m else None


def builtin_detect(page: dict) -> list:
    found = {}
    html = page["html"]
    meta = _meta_generator(html) or ""
    cookies = " ".join(page["cookies"])
    for name, category, source, pattern in SIGNATURES:
        if source == "html":
            hay = html
        elif source == "meta":
            hay = meta
        elif source == "cookie":
            hay = cookies
        else:
            hay = page["headers"].get(source.split(":", 1)[1], "")
        m = re.search(pattern, hay, re.I) if hay else None
        if m:
            entry = found.setdefault(name, {"name": name, "categories": [category], "versions": []})
            if m.groups() and m.group(1) and m.group(1) not in entry["versions"]:
                entry["versions"].append(m.group(1))
    if meta and not any(meta.lower().startswith(n.lower()) for n in found):
        found.setdefault(f"Generator: {meta}", {"name": f"Generator: {meta}",
                                               "categories": ["Generator"], "versions": []})
    return sorted(found.values(), key=lambda t: t["name"].lower())


def detect_technologies(url: str, page: dict) -> dict:
    """Use python-Wappalyzer if installed and working, else the built-in signatures."""
    engine, note = "builtin", None
    try:
        from Wappalyzer import Wappalyzer, WebPage
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage(page["final_url"], page["html"], page["headers"])
        result = wappalyzer.analyze_with_versions_and_categories(webpage)
        techs = [{"name": n, "versions": d.get("versions", []), "categories": d.get("categories", [])}
                 for n, d in sorted(result.items())]
        return {"engine": "wappalyzer", "technologies": techs, "note": note}
    except ImportError:
        note = "python-Wappalyzer not installed; used built-in signatures (pip install python-Wappalyzer)."
    except Exception as exc:  # signature download or library incompatibility
        note = f"Wappalyzer failed ({exc}); used built-in signatures."
    return {"engine": engine, "technologies": builtin_detect(page), "note": note}


# --------------------------------------------------------------------------
# SSL / TLS certificate audit
# --------------------------------------------------------------------------

def _fmt_name(rdns) -> str:
    return ", ".join(f"{k}={v}" for rdn in rdns for k, v in rdn)


def tls_info(host: str, port: int = 443, timeout: int = 10) -> dict:
    verify_error = None
    try:
        ctx = ssl.create_default_context()
        sock = socket.create_connection((host, port), timeout=timeout)
        tls = ctx.wrap_socket(sock, server_hostname=host)
    except ssl.SSLCertVerificationError as exc:
        verify_error = exc.verify_message or str(exc)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((host, port), timeout=timeout)
        tls = ctx.wrap_socket(sock, server_hostname=host)
    except (OSError, ssl.SSLError) as exc:
        raise RuntimeError(f"TLS connection to {host}:{port} failed: {exc}")

    with tls:
        cert = tls.getpeercert()
        der = tls.getpeercert(binary_form=True)
        protocol, cipher = tls.version(), tls.cipher()

    info = {"host": host, "port": port, "protocol": protocol,
            "cipher": cipher[0] if cipher else None,
            "chain_verified": verify_error is None, "verify_error": verify_error,
            "subject": None, "issuer": None, "not_before": None, "not_after": None,
            "days_remaining": None, "san": [], "serial": None, "notes": []}

    if cert:  # populated only for verified connections
        info["subject"] = _fmt_name(cert.get("subject", ()))
        info["issuer"] = _fmt_name(cert.get("issuer", ()))
        info["serial"] = cert.get("serialNumber")
        nb, na = cert.get("notBefore"), cert.get("notAfter")
        info["not_before"], info["not_after"] = nb, na
        info["san"] = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
        if na:
            exp = datetime.fromtimestamp(ssl.cert_time_to_seconds(na), tz=timezone.utc)
            info["days_remaining"] = (exp - datetime.now(timezone.utc)).days
    elif der:  # unverified: parse DER with `cryptography` if available
        try:
            from cryptography import x509
            c = x509.load_der_x509_certificate(der)
            info["subject"] = c.subject.rfc4514_string()
            info["issuer"] = c.issuer.rfc4514_string()
            info["serial"] = format(c.serial_number, "x")
            nb = getattr(c, "not_valid_before_utc", None) or c.not_valid_before.replace(tzinfo=timezone.utc)
            na = getattr(c, "not_valid_after_utc", None) or c.not_valid_after.replace(tzinfo=timezone.utc)
            info["not_before"], info["not_after"] = nb.isoformat(), na.isoformat()
            info["days_remaining"] = (na - datetime.now(timezone.utc)).days
            try:
                san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                info["san"] = san.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                pass
        except ImportError:
            info["notes"].append("Install `cryptography` to read details of certificates that fail verification.")

    if verify_error:
        info["notes"].append(f"Certificate chain did not verify: {verify_error}")
    if info["days_remaining"] is not None:
        if info["days_remaining"] < 0:
            info["notes"].append("Certificate has EXPIRED.")
        elif info["days_remaining"] < 30:
            info["notes"].append(f"Certificate expires in {info['days_remaining']} days.")
    if protocol in ("TLSv1", "TLSv1.1", "SSLv3"):
        info["notes"].append(f"Negotiated legacy protocol {protocol}.")
    others = sorted({s for s in info["san"] if s.lower() != host.lower() and not s.startswith("*.")})
    if others:
        info["notes"].append(f"SANs list {len(others)} other hostname(s) - review for related/internal sites.")
    return info


# --------------------------------------------------------------------------
# HTTP security header audit
# --------------------------------------------------------------------------

def audit_headers(page: dict) -> dict:
    h = page["headers"]
    https = page["final_url"].lower().startswith("https://")
    csp = h.get("content-security-policy", "")
    checks = []

    def add(header, present, value, severity_if_missing, advice, ok_note=""):
        checks.append({"header": header, "present": present, "value": value or "",
                       "severity": "ok" if present else severity_if_missing,
                       "advice": ok_note if present else advice})

    if https:
        add("Strict-Transport-Security", "strict-transport-security" in h,
            h.get("strict-transport-security"), "high",
            "Missing HSTS: browsers may connect over plain HTTP. Add e.g. max-age=31536000; includeSubDomains.")
    else:
        checks.append({"header": "Strict-Transport-Security", "present": False, "value": "",
                       "severity": "medium", "advice": "Site was reached over HTTP; serve it over HTTPS and add HSTS."})
    add("Content-Security-Policy", bool(csp), csp[:200], "high",
        "Missing CSP: no browser-enforced limit on script/style sources (XSS impact).")
    xfo = "x-frame-options" in h or "frame-ancestors" in csp.lower()
    add("X-Frame-Options", xfo, h.get("x-frame-options") or ("via CSP frame-ancestors" if xfo else ""),
        "medium", "Missing clickjacking protection: add X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.")
    nosniff = h.get("x-content-type-options", "").lower() == "nosniff"
    add("X-Content-Type-Options", nosniff, h.get("x-content-type-options"), "low",
        "Add X-Content-Type-Options: nosniff to prevent MIME sniffing.")
    add("Referrer-Policy", "referrer-policy" in h, h.get("referrer-policy"), "low",
        "Add a Referrer-Policy (e.g. strict-origin-when-cross-origin).")
    add("Permissions-Policy", "permissions-policy" in h, h.get("permissions-policy"), "low",
        "Add a Permissions-Policy to restrict browser features (camera, geolocation, ...).")

    disclosure = []
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        if name in h:
            disclosure.append({"header": name, "value": h[name],
                               "advice": "Discloses technology/version; consider removing or genericizing."})

    cookie_issues = []
    for raw in page["cookies"]:
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        missing = [flag for flag, token in (("Secure", "secure"), ("HttpOnly", "httponly"),
                                            ("SameSite", "samesite")) if token not in low]
        if missing:
            cookie_issues.append({"cookie": name, "missing": missing})

    return {"status": page["status"], "final_url": page["final_url"], "checks": checks,
            "disclosure": disclosure, "cookie_issues": cookie_issues}


# --------------------------------------------------------------------------
# OS discovery
# --------------------------------------------------------------------------

def _guess_from_ttl(ttl: int) -> tuple:
    initial = next(v for v in (32, 64, 128, 255) if ttl <= v)
    guess = {32: "Older Windows / embedded device", 64: "Linux / Unix / BSD / macOS / Android",
             128: "Windows", 255: "Network device / Solaris / some Unix"}[initial]
    return initial, guess


def os_discovery(host: str, use_nmap: bool = False, timeout: int = 120) -> dict:
    result = {"host": host, "ping_ttl": None, "initial_ttl": None, "estimated_hops": None,
              "ttl_guess": None, "nmap": None, "notes": []}
    flag = "-n" if platform.system() == "Windows" else "-c"
    try:
        proc = subprocess.run(["ping", flag, "1", host], capture_output=True, text=True,
                              timeout=15, check=False)
        m = re.search(r"ttl[=:\s]+(\d+)", proc.stdout, re.I)
        if m:
            ttl = int(m.group(1))
            initial, guess = _guess_from_ttl(ttl)
            result.update(ping_ttl=ttl, initial_ttl=initial, estimated_hops=initial - ttl, ttl_guess=guess)
        else:
            result["notes"].append("No ICMP reply (host/firewall may block ping), so TTL analysis was not possible.")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        result["notes"].append("`ping` unavailable or timed out.")

    if use_nmap:
        if not shutil.which("nmap"):
            result["notes"].append("nmap not found on PATH (sudo apt install nmap).")
        else:
            try:
                proc = subprocess.run(["nmap", "-O", "--osscan-guess", "-Pn", "-T2", host],
                                      capture_output=True, text=True, timeout=timeout, check=False)
                lines = [ln.strip() for ln in proc.stdout.splitlines()
                         if re.match(r"\s*(Running|OS details|Aggressive OS guesses|Device type|"
                                     r"OS CPE|No exact OS matches)", ln)]
                result["nmap"] = lines or ["No OS information returned."]
                if "root" in proc.stdout.lower() or "requires root" in proc.stderr.lower():
                    result["notes"].append("Nmap -O needs root privileges (run with sudo).")
            except subprocess.TimeoutExpired:
                result["notes"].append(f"nmap timed out after {timeout}s.")
    result["notes"].append("TTL analysis is a heuristic; proxies/CDNs answer on behalf of the origin.")
    return result
