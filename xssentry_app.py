#!/usr/bin/env python3
"""
xssentry_app.py

Launches the XSSentry Web Application Dashboard.
Usage:
    python xssentry_app.py
    python xssentry_app.py --port 8888 --host 127.0.0.1
"""

import argparse
import os
import sys

# Ensure root directory is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from xssentry.app import start_server


def main():
    parser = argparse.ArgumentParser(description="XSSentry Web Application Dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8888, help="Port number (default: 8888)")
    parser.add_argument("--no-browser", action="store_true", help="Do not auto-open the browser")
    args = parser.parse_args()

    start_server(host=args.host, port=args.port, open_browser=not args.no_browser)


if __name__ == "__main__":
    main()
