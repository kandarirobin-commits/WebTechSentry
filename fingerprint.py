#!/usr/bin/env python3
"""
WebTechSentry - command-line interface.

  python3 fingerprint.py URL                 legacy WhatWeb-only scan
  python3 fingerprint.py URL --phase1        passive recon & OSINT
  python3 fingerprint.py URL --phase2        fingerprinting (tech, TLS, headers, OS)
  python3 fingerprint.py URL --all           everything, including WhatWeb
  python3 fingerprint.py URL --modules dns,tls,headers

See gui_qt.py for the PySide6 graphical version.
"""

import argparse
import sys

import core
from core import DEFAULT_AGGRESSION, DEFAULT_TIMEOUT, scan, whatweb_available


def main():
    parser = argparse.ArgumentParser(
        prog="fingerprint.py",
        description="WebTechSentry - authorized web reconnaissance and technology fingerprinting.",
    )
    parser.add_argument("url", help="Target URL, e.g. https://your-authorized-site.example")
    parser.add_argument("--phase1", action="store_true",
                        help="Passive recon: " + ", ".join(core.PHASE1_KEYS))
    parser.add_argument("--phase2", action="store_true",
                        help="Fingerprinting: " + ", ".join(core.PHASE2_KEYS))
    parser.add_argument("--whatweb", action="store_true", help="Also run the WhatWeb scan.")
    parser.add_argument("--all", action="store_true", help="Run every module.")
    parser.add_argument("--modules", help="Comma-separated module list, from: " + ", ".join(core.ALL_MODULES))
    parser.add_argument("--nmap", action="store_true",
                        help="Add an Nmap -O OS scan to OS discovery (active; usually needs root).")
    parser.add_argument("--aggression", type=int, default=DEFAULT_AGGRESSION, choices=[1, 2, 3, 4],
                        help="WhatWeb aggression level (default: 1, low/passive).")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"WhatWeb timeout in seconds (default: {DEFAULT_TIMEOUT}).")
    parser.add_argument("--out", default="reports",
                        help="Directory to write JSON/CSV reports into (default: ./reports).")
    args = parser.parse_args()

    # Select modules
    selected = set()
    if args.all:
        selected = set(core.ALL_MODULES)
    if args.phase1:
        selected |= set(core.PHASE1_KEYS)
    if args.phase2:
        selected |= set(core.PHASE2_KEYS)
    if args.whatweb:
        selected.add("whatweb")
    if args.modules:
        chosen = {m.strip() for m in args.modules.split(",") if m.strip()}
        unknown = chosen - set(core.ALL_MODULES)
        if unknown:
            print(f"Unknown module(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            return 2
        selected |= chosen

    # Legacy behaviour: no module flags -> original WhatWeb scan and report format
    if not selected:
        if not whatweb_available():
            print("[!] 'whatweb' was not found on PATH.\n"
                  "    Install it first, e.g.: sudo apt update && sudo apt install whatweb",
                  file=sys.stderr)
            return 3
        try:
            print("[*] Running WhatWeb scan...")
            result = scan(args.url, args.aggression, args.timeout, args.out)
        except ValueError as exc:
            print(f"Input error: {exc}", file=sys.stderr)
            return 2
        print(f"[+] JSON report: {result['json_path']}")
        print(f"[+] CSV summary: {result['csv_path']}")
        if result["findings"]:
            print(f"[+] Parsed {len(result['findings'])} technology signal(s). Validate independently before relying on them.")
        if result["record"]["return_code"] not in (0, None):
            print("[!] Non-zero exit status; inspect stderr in the JSON report.")
        return 0

    try:
        result = core.assess(args.url, selected, args.aggression, args.timeout, args.out,
                             use_nmap=args.nmap, progress=lambda msg: print(f"[*] {msg}"))
    except ValueError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2

    print()
    for line in core.summarize(result):
        print(f"  - {line}")
    print()
    print(f"[+] JSON report: {result['json_path']}")
    print(f"[+] CSV summary: {result['csv_path']}")
    print("[i] Findings are clues, not proof. Validate important results manually.")
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
