#!/usr/bin/env python3
"""
xssentry_desktop.py

Direct launcher for the XSSentry Native Desktop Application.
Usage:
    python xssentry_desktop.py
    python xssentry_desktop.py https://target-url.com
"""

import argparse
import os
import sys

# Ensure this project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from xssentry.desktop import start_desktop


def main():
    parser = argparse.ArgumentParser(description="XSSentry Native Desktop Application")
    parser.add_argument("target", nargs="?", default=None, help="Optional initial target URL")
    parser.add_argument("--port", "-p", type=int, default=8888, help="Internal port (default: 8888)")
    args = parser.parse_args()

    start_desktop(target_url=args.target, port=args.port)


if __name__ == "__main__":
    main()
