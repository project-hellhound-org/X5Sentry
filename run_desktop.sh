#!/usr/bin/env bash
#
# XSSentry Desktop App Launcher
#

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PY="$DIR/.venv/bin/python"

if [ -f "$VENV_PY" ]; then
    exec "$VENV_PY" "$DIR/xssentry_desktop.py" "$@"
else
    exec python3 "$DIR/xssentry_desktop.py" "$@"
fi
