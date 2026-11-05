# WebTechSentry

**Authorized web reconnaissance and technology fingerprinting — passive OSINT, stack/TLS/header/OS fingerprinting, WhatWeb, a CLI and a PySide6 desktop GUI.**

WebTechSentry runs a set of recon modules against **one explicit target URL** and writes a timestamped **JSON report** and **CSV summary**. It is a reconnaissance and reporting aid, **not** a vulnerability scanner: every finding is a clue, not proof.

**Only scan assets you own or have explicit written authorization to test.**

---

## Modules

### Phase 1 — Passive reconnaissance & OSINT (no probing of the target's web server)

| Module | Key | What it does |
|---|---|---|
| WHOIS | `whois` | Registrar, creation/expiry/update dates, name servers, status, contact emails |
| DNS + email security | `dns` | A, AAAA, MX, NS, TXT, CNAME, SOA; parses SPF and `_dmarc` and flags weak/missing policy |
| Subdomains | `subdomains` | Certificate Transparency mining via crt.sh (no brute-forcing) |
| OSINT harvest | `osint` | Regex extraction of emails, phone candidates, hostnames and IPs from **archived** pages (Wayback Machine) |

### Phase 2 — Infrastructure & technology fingerprinting (contacts the target)

| Module | Key | What it does |
|---|---|---|
| Tech stack | `tech` | python-Wappalyzer if installed, otherwise built-in signatures: CMS, JS frameworks, analytics, web servers, CDN, languages |
| SSL/TLS | `tls` | Issuer, subject, validity dates, days remaining, protocol/cipher, SANs, chain verification result |
| Security headers | `headers` | Flags missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy; version-disclosing headers; cookie flags |
| OS discovery | `os` | ICMP TTL analysis (initial TTL, hop estimate); optional `nmap -O` |
| WhatWeb | `whatweb` | Original WhatWeb scan (off by default in the GUI) |

Each module is isolated: if one fails (e.g. crt.sh rate-limits you) the rest still run and the error is recorded in the report.

---

## Installation

```bash
sudo apt update
sudo apt install whois whatweb nmap dnsutils   # whatweb/nmap/dig are optional
pip install -r requirements.txt
```

Keep `core.py`, `passive.py`, `fingerprint_tech.py`, `fingerprint.py`, `gui_qt.py` (and optionally `gui.py`) in one folder.

Python 3.8+ required. The legacy Tk GUI (`gui.py`) additionally needs `python3-tk`.

---

## Usage

### PySide6 GUI

```bash
python3 gui_qt.py
```

Enter the URL, tick the modules you want, confirm the authorization checkbox (the Run button stays disabled until you do), and click **Run Assessment**. Each module gets its own tab; rows are color-coded by severity, and an Overview tab summarizes the highlights.

### CLI

```bash
python3 fingerprint.py https://your-authorized-site.example               # legacy WhatWeb-only scan
python3 fingerprint.py https://your-authorized-site.example --phase1      # passive recon
python3 fingerprint.py https://your-authorized-site.example --phase2      # tech, TLS, headers, OS
python3 fingerprint.py https://your-authorized-site.example --all         # everything incl. WhatWeb
python3 fingerprint.py https://your-authorized-site.example --modules dns,tls,headers
python3 fingerprint.py https://your-authorized-site.example --phase2 --nmap   # add nmap -O (needs root)
```

Options: `--aggression {1..4}`, `--timeout`, `--out DIR` (WhatWeb settings and report folder).

---

## Output

- `reports/assessment_<timestamp>.json` — full structured results, per module, plus errors.
- `reports/assessment_<timestamp>.csv` — flat rows: `target, timestamp_utc, module, item, value, detail, severity`.
- Running with no module flags keeps the original `fingerprint_*.json` / `summary_*.csv` WhatWeb output.

---

## Project structure

```
webtech-sentry/
├── core.py              # shared engine: scan(), assess(), reports
├── passive.py           # Phase 1: WHOIS, DNS, crt.sh, OSINT
├── fingerprint_tech.py  # Phase 2: tech, TLS, headers, OS
├── gui_qt.py            # PySide6 GUI
├── gui.py               # legacy Tkinter GUI (WhatWeb only)
├── fingerprint.py       # CLI
├── requirements.txt
├── LICENSE
└── reports/             # created on first run
```

---

## Boundaries (by design)

- No exploitation, credential attacks, authentication bypass, or vulnerability verification.
- No brute-force subdomain guessing, stealth/evasion, or high-volume scanning.
- One explicit URL per run; no automatic target lists.
- Phase 2 is light-touch: one HTTP GET, one TLS handshake, one ping. `nmap -O` is opt-in.

## Limitations

- Phone numbers are regex candidates and can be false positives.
- OSINT relies on what the Wayback Machine has archived; search-engine scraping is intentionally not used (fragile and against most terms of service).
- TTL-based OS detection is a heuristic; CDNs, proxies and firewalls answer for the origin. TCP window-size analysis requires raw sockets, so it is only available through Nmap.
- The TLS module audits the leaf certificate; unverifiable certificates need the `cryptography` package to be parsed.
- crt.sh is occasionally slow or rate-limited.
- CDNs/WAFs can mask the true stack; signature databases can be incomplete or outdated.

## License

MIT — see [LICENSE](./LICENSE). Includes an additional project-policy clause restricting use to authorized targets.

## References

- [WhatWeb](https://github.com/urbanadventurer/WhatWeb) · [Wappalyzer (python)](https://github.com/chorsley/python-Wappalyzer) · [crt.sh](https://crt.sh)
- [Qt for Python (PySide6)](https://doc.qt.io/qtforpython-6/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
