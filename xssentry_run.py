#!/usr/bin/env python3
"""
XSSENTRY — Autonomous XSS Hunter (HELLHOUND-engine)
Root-level CLI wrapper. Delegates to xssentry.main.
"""
import sys
import os

# Ensure this project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from xssentry.main import main

if __name__ == "__main__":
    main()
