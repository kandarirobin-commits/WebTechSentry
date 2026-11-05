#!/usr/bin/env bash
# WebTechSentry launcher for Linux / macOS:  ./run.sh   (or ./run.sh --cli URL --all)
cd "$(dirname "$0")" || exit 1
if command -v python3 >/dev/null 2>&1; then
  exec python3 run.py "$@"
elif command -v python >/dev/null 2>&1; then
  exec python run.py "$@"
else
  echo "Python 3 is not installed. Install it first (Debian/Ubuntu/Kali: sudo apt install python3 python3-venv python3-pip)."
  exit 1
fi
