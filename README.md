<p align="center">
  <img src="Image/sentry.jpeg" alt="X5Sentry" width="600"/>
</p>

<h1 align="center">X5Sentry</h1>

<p align="center">
  Autonomous XSS Hunter — Maps attack surfaces, analyzes character survivability, and validates vulnerabilities through headless browser automation.
  <br>
  <br>
  <code style="color: #ff2244; font-weight: bold;">[ UNDER DEVELOPMENT ]</code>
  <br>
  <i>Expect architectural shifts and potential false positives as we constantly optimize for high-fidelity detection.</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/version-5.0-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-GPL--3.0-blue?style=flat-square"/>
</p>

---

## Overview

X5Sentry is an autonomous Cross-Site Scripting scanner that maps a web application's full attack surface and systematically tests every input point. It handles **Reflected**, **Stored**, **DOM-based**, **Mutation (mXSS)**, **Universal (uXSS)**, and **Blind XSS** vectors across a single unified scan pipeline.

The scanner prioritises accuracy over noise by combining static reflection analysis with real browser-side execution. Every high-confidence finding is confirmed in a headless Chromium instance using a cryptographic token-verified dialog handler — if the browser does not fire our exact payload, the finding is discarded. For every confirmed vulnerability, **visual evidence** (OS-level or viewport screenshot) is saved to the `./evidence/` directory.

Reconnaissance is fully handled by the integrated [Hellhound Spider](https://github.com/l4zz3rj0d/Hellhound-Spider) — X5Sentry feeds directly from its output with no extra steps required.

---

## Installation

### Quick Setup

X5Sentry runs inside an isolated virtual environment. The installer automates venv creation, dependency installation, Chromium provisioning, and global command deployment.

```bash
git clone https://github.com/project-hellhound-org/X5Sentry.git
cd X5Sentry
chmod +x install.sh
./install.sh
```

The installer creates a `.venv`, installs all dependencies (including Playwright's Chromium), and deploys a global wrapper to `/usr/local/bin/xssentry`. You can now run the tool from **any directory**:

```bash
xssentry https://target.com
```

### Update

To pull the latest changes and refresh your virtual environment:

```bash
./update.sh
```

---

## Architecture

X5Sentry v5.0 is fully modularised into a Python package structure:

```
X5Sentry/
├── xssentry/                    # Core Python package
│   ├── main.py                  # CLI entry point & scan orchestrator
│   ├── spider_integration.py    # Hellhound Spider bridge
│   ├── core/
│   │   ├── http_client.py       # Session-aware HTTP client
│   │   ├── verifier.py          # Static reflection & context analysis
│   │   ├── validator.py         # Playwright zero-false-positive engine
│   │   └── poc.py               # PoC generator
│   ├── engines/
│   │   ├── reflected.py         # Reflected XSS scanner
│   │   ├── stored.py            # Autonomous Stored XSS agent
│   │   ├── dom.py               # DOM XSS static analyser
│   │   ├── mutation.py          # mXSS & uXSS engines
│   │   └── blind.py             # Blind XSS OOB scanner
│   ├── payloads/
│   │   ├── reflected_payloads.py
│   │   ├── mxss_uxss_payloads.py
│   │   └── blind_payloads.py
│   ├── servers/
│   │   └── cookie_catcher.py    # Local cookie-catch listener
│   ├── ui/
│   │   ├── hud.py               # Real-time Cyber Tactical HUD
│   │   └── reports.py           # Terminal, JSON & HTML reports
│   └── utils/
│       ├── helpers.py
│       ├── colors.py
│       └── regex_patterns.py
├── spider.py                    # Hellhound Spider (bundled)
├── xssentry_run.py              # Root-level CLI wrapper
├── install.sh                   # Automated setup script
├── update.sh                    # Update & refresh script
├── setup.py                     # pip-installable package config
└── requirements.txt
```

---

## Scan Pipeline

X5Sentry executes a multi-phase autonomous audit pipeline:

### Phase 1 — Reconnaissance
The integrated Hellhound Spider crawls the target and discovers endpoints, parameters, hidden fields, and JavaScript-extracted API routes. Includes `robots.txt`/`sitemap.xml` parsing and wordlist-based parameter fuzzing.

### Phase 2 — Reflected XSS
Tests every discovered parameter with context-aware payloads. Each candidate is first verified via static response analysis (reflection + context detection), then confirmed in a live Chromium browser.

### Phase 3 — Stored XSS
An autonomous feedback-driven agent that:
1. **Classifies filters** — probes how the target transforms input (`stripped`, `encoded`, `escaped_js`, `waf_block`, `mixed`).
2. **Generates contextual bypasses** — up to 15 variants per filter class (case-mangling, null-byte injection, double-encoding, base64 eval, JS escapes).
3. **Maps data flow** — injects unique markers into writable endpoints, then scans all display pages for reflection.
4. **Confirms in-browser** — Playwright execution verification before recording any finding.

### Phase 4 — DOM XSS
Static analysis of JavaScript sources to identify dangerous sink/source patterns (`document.write`, `innerHTML`, `eval`, `location.hash`, etc.) combined with runtime parameter probing.

### Phase 5 — Mutation XSS (mXSS)
Tests mutation-based payloads against POST/PUT endpoints where HTML sanitisers may reparse and mutate safe input into executable markup.

### Phase 6 — Universal XSS (uXSS)
Uses Playwright's runtime SOP (Same-Origin Policy) analysis. A finding is classified as TRUE UXSS **only** when `page.evaluate()` proves the browser's sandbox boundary is breached (`SOP_FAILURE`). If the dialog fires but SOP remains intact, the finding is downgraded to standard Reflected XSS — zero false UXSS classifications.

### Phase 7 — Blind XSS
Embeds a self-hosted OOB callback server. Blind payloads carry a unique token in the URL — any incoming hit is a confirmed out-of-band execution.

---

## Zero-False-Positive Validation Engine

The Playwright-based validator implements a strict 4-phase pipeline:

| Phase | Mechanism | Purpose |
|---|---|---|
| **1. Cryptographic Token** | Inject `X5-PROOF-{uuid}` into payload's alert/confirm/prompt | Bind each dialog to the exact payload that produced it |
| **2. Dialog Integrity Check** | Strict match: `X5-PROOF-{token}` must appear in `dialog.message` | Eliminate site popups, ads, error dialogs, consent banners |
| **3. SOP Runtime Analysis** | `page.evaluate()` attempts cross-origin boundary read | Classify UXSS vs Reflected — only `SOP_FAILURE` = true UXSS |
| **4. OS Pixel Capture** | PyAutoGUI captures the native OS dialog window | Produce visual evidence with the alert physically visible |

---

## Usage

```bash
xssentry <target> [options]
```

### Testing Options

| Flag | Default | Description |
|---|---|---|
| `-t`, `--threads` | `10` | Concurrent XSS test workers |
| `--timeout` | `8` | HTTP timeout per request (seconds) |
| `--delay` | `0.0` | Delay between requests in seconds |
| `--max-pages` | `80` | Max pages for the spider to crawl |

### Authentication

| Flag | Description |
|---|---|
| `--cookie` | Session cookie or Authorization header for authenticated scans |
| `--cookie-port` | Port for the local cookie-catch listener (default: 8765) |
| `--cookie-catcher` | External cookie catcher URL (skips local server) |

### Blind XSS

| Flag | Description |
|---|---|
| `--blind-port` | Port for the embedded OOB callback server (0=random, -1=disable) |

### Feature Flags

| Flag | Description |
|---|---|
| `--no-stored` | Skip stored XSS scan |
| `--no-dom` | Skip DOM XSS static analysis |
| `--no-blind` | Skip blind XSS scan |
| `--no-fuzz` | Skip wordlist parameter fuzzing |
| `--no-cookie-server` | Disable the local cookie-catch listener |
| `--headless` | Force headless Playwright mode (disables OS-level screenshots) |

### Output

| Flag | Description |
|---|---|
| `-o`, `--output` | Save full findings to a JSON report |
| `--html-report` | Generate a styled HTML report (default: `xss_report.html`) |
| `-v`, `--verbose` | Show verbose spider and test output |

---

## Examples

```bash
# Standard autonomous scan — spider + all engines
xssentry https://target.com

# Increase concurrent test workers
xssentry https://target.com -t 20

# Authenticated scan
xssentry https://target.com --cookie "session=abc123; csrf=xyz"

# Save results to JSON
xssentry https://target.com -o report.json

# Generate HTML report
xssentry https://target.com --html-report findings.html

# Enable blind XSS OOB listener on a specific port
xssentry https://target.com --blind-port 9001

# Skip DOM and blind scan for speed
xssentry https://target.com --no-dom --no-blind

# CI / display-less environment
xssentry https://target.com --headless -o ci_report.json
```

---

## Requirements

- Python 3.10+
- `playwright`, `aiohttp`, `beautifulsoup4`, `lxml`, `rich`, `pyautogui`, `Pillow`
- Chromium (installed automatically via `install.sh`)

---

## License

For authorized security testing only. This software is licensed under the **GNU General Public License v3 (GPLv3)**.

---

## Authors

<a href="https://github.com/L33TxGH05T">
  <img src="https://img.shields.io/badge/Lead--Developer-L33TxGH05T-1a1a1a?style=for-the-badge" alt="L33TxGH05T"/>
</a>
<a href="https://l4zz3rj0d.github.io">
  <img src="https://img.shields.io/badge/Core--Developer-L4ZZ3RJ0D-c0392b?style=for-the-badge" alt="L4ZZ3RJ0D"/>
</a>
