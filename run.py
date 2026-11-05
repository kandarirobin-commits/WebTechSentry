#!/usr/bin/env python3
"""
WebTechSentry launcher - one command to set up and start the app.

    python run.py                 first run: creates .venv, installs PySide6 etc., opens the GUI
    python run.py --cli URL ...   run the command-line version (same options as fingerprint.py)
    python run.py --setup-only    just install everything, don't launch
    python run.py --reinstall     rebuild the environment from scratch

Uses only the Python standard library, so it works before anything is installed.
"""

import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path

HERE = Path(__file__).resolve().parent
VENV = HERE / ".venv"
MARKER = VENV / ".webtechsentry_deps_ok"

REQUIRED = ["PySide6", "dnspython"]
OPTIONAL = ["cryptography", "python-Wappalyzer", "python-whois"]  # app works without these


def say(msg=""):
    print(msg, flush=True)


def venv_python() -> Path:
    return VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def run(cmd, **kw):
    return subprocess.run([str(c) for c in cmd], **kw)


def create_venv():
    say("[1/3] Creating private Python environment (.venv)...")
    try:
        venv.EnvBuilder(with_pip=True, clear=VENV.exists()).create(VENV)
    except Exception as exc:
        say(f"\n[!] Could not create the environment: {exc}")
        if sys.platform.startswith("linux"):
            say("    On Debian/Ubuntu/Kali install the venv module first:\n"
                "      sudo apt install python3-venv python3-pip")
        sys.exit(1)
    if not venv_python().exists():
        say("[!] Environment was created but its Python was not found.")
        sys.exit(1)


def pip_install(packages, required):
    py = venv_python()
    for pkg in packages:
        say(f"      installing {pkg}...")
        proc = run([py, "-m", "pip", "install", "--disable-pip-version-check", "-q", pkg],
                   capture_output=True, text=True)
        if proc.returncode != 0:
            if required:
                say(f"\n[!] Failed to install {pkg}:\n{proc.stderr.strip()[-1500:]}")
                say("    Check your internet connection. PySide6 supports Python 3.9-3.13 "
                    f"(you have {sys.version.split()[0]}).")
                sys.exit(1)
            say(f"      (optional package {pkg} skipped)")


def setup(force=False):
    if force and VENV.exists():
        say("Removing old environment...")
        shutil.rmtree(VENV, ignore_errors=True)
    if MARKER.exists() and venv_python().exists():
        return
    if not venv_python().exists():
        create_venv()
    say("[2/3] Installing required packages (PySide6 is large, this can take a few minutes)...")
    run([venv_python(), "-m", "pip", "install", "--disable-pip-version-check", "-q", "--upgrade", "pip"],
        capture_output=True)
    pip_install(REQUIRED, required=True)
    say("[3/3] Installing optional packages...")
    pip_install(OPTIONAL, required=False)
    MARKER.write_text("ok\n")
    say("Setup complete.\n")


def main():
    args = sys.argv[1:]
    if sys.version_info < (3, 8):
        say("Python 3.8 or newer is required.")
        return 1

    force = "--reinstall" in args
    setup_only = "--setup-only" in args
    args = [a for a in args if a not in ("--reinstall", "--setup-only")]
    setup(force)
    if setup_only:
        say("Start the app with:  python run.py")
        return 0

    py = venv_python()
    if args and args[0] == "--cli":
        return run([py, HERE / "fingerprint.py", *args[1:]]).returncode

    if sys.platform.startswith("linux") and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        say("No graphical display detected (SSH/headless). Use the CLI instead:\n"
            "  python run.py --cli https://your-authorized-site.example --all")
        return 1

    code = run([py, HERE / "gui_qt.py", *args]).returncode
    if code != 0 and sys.platform.startswith("linux"):
        say("\nIf the error mentioned the Qt platform plugin 'xcb', install:\n"
            "  sudo apt install libxcb-cursor0 libxkbcommon-x11-0 libegl1")
    return code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
