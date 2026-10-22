<p align="center">
  <img src="Image/logo.png" alt="X5Sentry" width="320"/>
</p>

<h1 align="center">X5Sentry</h1>

<p align="center">
  AI-Powered Autonomous XSS Hunter — an agentic tool-calling engine driven by NVIDIA NIM (Nemotron) that maps attack surfaces, selects context-aware payloads, and validates vulnerabilities through headless browser automation.
  <br>
  <br>
  <code style="color: #ff2244; font-weight: bold;">[ UNDER DEVELOPMENT ]</code>
  <br>
  <i>Expect architectural shifts and potential false positives as we constantly optimize for high-fidelity detection.</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9+-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/version-5.0-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/AI--Engine-NVIDIA%20NIM%20Nemotron-76B900?style=flat-square&logo=nvidia&logoColor=white"/>
  <img src="https://img.shields.io/badge/spider-Hellhound%20v13.x-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-GPL--3.0-blue?style=flat-square"/>
</p>

---

## What Changed in v5.0

X5Sentry v5.0 is a ground-up architectural rewrite. The previous version was a pipeline-based scanner that executed a fixed sequence of phases. **v5.0 replaces that entire pipeline with an AI agent** — a tool-calling loop powered by NVIDIA NIM (Nemotron 120B) that decides _what_ to do, _when_ to do it, and _how_ to adapt.

| | **v5.1 (Previous)** | **v5.0-AI (Current)** |
|---|---|---|
| **Brain** | Hard-coded scan pipeline | LLM agent with tool-calling loop |
| **Decision-making** | Fixed phase sequence | AI reasons about each step dynamically |
| **Payload selection** | Brute-force all payloads | Context-aware, AI-selected payloads |
| **User interaction** | CLI flags only | Interactive chat console + slash commands |
| **Interface** | Terminal only | Terminal, Web Dashboard, Desktop App |
| **Skill system** | None | 60+ structured XSS techniques (queryable knowledge base) |
| **Stored XSS** | Fixed injection → check | AI-driven form discovery, CSRF extraction, submit → verify |
| **Safety** | Implicit | Hard-coded confirmation gate — exploitation requires explicit user `yes` |

---

## Overview

X5Sentry is an autonomous Cross-Site Scripting hunter built on an agentic AI architecture. Instead of running a fixed pipeline, the tool deploys an **NVIDIA NIM-powered agent** (Nemotron 120B) that:

1. **Reasons** about the target — examining responses, headers, WAF behavior, and reflection contexts
2. **Selects tools** — calling reconnaissance, spidering, payload generation, form submission, and exploitation tools through a structured tool-calling interface
3. **Adapts** — adjusting its strategy based on what it discovers (filter types, encoding behaviors, context changes)
4. **Confirms** — every exploitation attempt requires explicit user approval through a hard-coded safety gate

The scanner covers **Reflected**, **Stored**, **DOM-based**, **Mutation (mXSS)**, and **Blind XSS** vectors. All critical findings are validated through Playwright headless browser execution.

Reconnaissance is handled by the integrated [Hellhound Spider](https://github.com/l4zz3rj0d/Hellhound-Spider) (~9,400 lines) — a deep SPA-rendering crawler with WAF/CDN fingerprinting, TLS inspection, DNS intelligence, tech-stack profiling, and Wayback Machine enumeration.

---

## Installation

### Quick Setup

```bash
git clone https://github.com/project-hellhound-org/X5Sentry.git
cd X5Sentry
chmod +x install.sh
./install.sh
```

The installer creates a `.venv`, installs all dependencies (including Playwright's Chromium), and deploys a global wrapper to `/usr/local/bin/xssentry`.

### NVIDIA API Key

X5Sentry requires an NVIDIA NIM API key for the AI agent brain. Get one at [build.nvidia.com](https://build.nvidia.com/).

Set it via any of these methods:

```bash
# Environment variable
export NVIDIA_API_KEY="nvapi-..."

# CLI flag
xssentry --api-key "nvapi-..."

# Persistent config
mkdir -p ~/.xssentry
echo '{"nvidia_api_key": "nvapi-..."}' > ~/.xssentry/config.json
```

### Update

```bash
./update.sh
```

---

## Architecture

X5Sentry v5.0 uses an agentic tool-calling architecture modeled on the NVIDIA NIM function-calling API:

```
                    ┌─────────────────────┐
                    │     User Input       │
                    │  (Chat / CLI / Web)  │
                    └─────────┬───────────┘
                              │
                    ┌─────────▼───────────┐
                    │    AgentBrain        │
                    │  (llm_brain.py)      │
                    │                     │
                    │  NVIDIA NIM API      │
                    │  Nemotron 120B       │
                    │  Tool-calling loop   │
                    └─────────┬───────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
     ┌────────▼──────┐ ┌─────▼──────┐ ┌──────▼───────┐
     │  Recon Tools   │ │ XSS Tools  │ │ Skill Engine │
     │                │ │            │ │              │
     │ • run_recon    │ │ • test_    │ │ • analyse_   │
     │ • run_spider   │ │   payload  │ │   target_    │
     │ • get_payloads │ │ • submit_  │ │   skills     │
     │ • generate_    │ │   form     │ │ • learn_new_ │
     │   adaptive_    │ │            │ │   skill      │
     │   payload      │ │            │ │              │
     └───────────────┘ └─────┬──────┘ └──────────────┘
                              │
                    ┌─────────▼───────────┐
                    │   Safety Gate        │
                    │   (exploit.py)       │
                    │                     │
                    │  _EXPLOITATION_     │
                    │  APPROVED flag      │
                    │  User must say YES  │
                    └─────────────────────┘
```

### Package Structure

```
X5Sentry/
├── xssentry/                     # Core Python package
│   ├── __init__.py               # Version & metadata
│   ├── cli.py                    # CLI entry point & argument parsing
│   ├── chat.py                   # Rich interactive chat console
│   ├── llm_brain.py              # AgentBrain — NVIDIA NIM tool-calling loop
│   ├── guard.py                  # ScopeGuard, RateLimiter, CircuitBreaker
│   ├── recon.py                  # Tool: run_recon — HTTP fetch + HTML analysis
│   ├── spider.py                 # Tool: run_spider — Hellhound Spider bridge
│   ├── hellhound_spider.py       # Hellhound Spider v13.x (~9,400 lines)
│   ├── payloads.py               # Tool: get_payloads, generate_adaptive_payload
│   ├── exploit.py                # Tool: test_payload — Playwright validation
│   ├── form_submit.py            # Tool: submit_form — CSRF-aware form submission
│   ├── xss_skills.py             # Skill DB: 60+ XSS techniques + skill matcher
│   ├── app.py                    # Web Application backend (aiohttp + SSE)
│   ├── desktop.py                # Native desktop app (PyQt6 WebEngine)
│   └── web/                      # Web dashboard SPA (cyberpunk UI)
│       ├── index.html
│       └── static/
│           ├── css/
│           ├── js/
│           └── img/
├── spider.py                     # Hellhound Spider (standalone, bundled)
├── xssentry_run.py               # Root-level CLI wrapper
├── xssentry_app.py               # Web app launcher
├── xssentry_desktop.py           # Desktop app launcher
├── install.sh                    # Automated setup (venv + Chromium)
├── update.sh                     # Pull + refresh script
├── setup.py                      # pip-installable package config
└── requirements.txt
```

---

## Agent Tools

The AI brain has access to these registered tools. It decides when and how to call them:

| Tool | Module | Description |
|---|---|---|
| `run_recon` | `recon.py` | HTTP fetch + full HTML analysis — forms, parameters, headers, security fingerprinting |
| `run_spider` | `spider.py` | Launches Hellhound Spider for deep crawling, SPA rendering, Wayback enumeration |
| `get_payloads` | `payloads.py` | Retrieves categorized payloads (reflected, attribute, SVG, template, DOM, polyglot, encoding) |
| `generate_adaptive_payload` | `payloads.py` | Generates context-aware payloads based on reflection analysis |
| `test_payload` | `exploit.py` | Tests XSS payload against target — static reflection analysis + Playwright browser validation |
| `submit_form` | `form_submit.py` | CSRF-aware form submission for Stored XSS — auto-extracts tokens, verifies reflection |
| `analyse_target_skills` | `xss_skills.py` | Queries the 60+ technique skill database against current target context |
| `learn_new_skill` | `xss_skills.py` | Persists novel discovered bypass patterns as new skills for future scans |

---

## XSS Skill Knowledge Base

The skill engine (`xss_skills.py`) contains **60+ structured XSS hunting techniques** organized by type and difficulty:

| XSS Type | Beginner | Intermediate | Advanced |
|---|---|---|---|
| **Reflected** | Input reflection discovery, basic tag injection, attribute breakout | Context-aware payloads, encoding bypasses, polyglot injection | WAF evasion chains, mutation fuzzing, protocol handler abuse |
| **Stored** | Form-based injection, comment/profile field testing | CSRF-aware multi-step submission, data flow mapping | Filter classification, adaptive bypass generation (15 variants/filter) |
| **DOM** | Source-sink pattern detection, `innerHTML`/`document.write` analysis | Framework-specific DOM patterns, `postMessage` interception | Prototype pollution chains, service worker injection |
| **Blind** | OOB callback embedding, basic external resource loading | Token-verified out-of-band execution, DNS exfiltration | Delayed execution timing, polyglot blind payloads |
| **CSTI/Mutation** | Template syntax detection, basic `{{expression}}` injection | Framework-specific CSTI (Angular, Vue, Pug) | mXSS via HTML sanitizer reparsing, namespace confusion |

The `SkillMatcher` scores and ranks applicable techniques based on target reconnaissance data. The `DynamicSkillStore` persists novel bypass patterns discovered during scans.

---

## Safety Model

X5Sentry implements a **hard-coded confirmation gate** — the LLM cannot bypass it:

1. **Scope Guard** (`guard.py`) — All tool URLs are validated against the authorized target. Out-of-scope requests are rejected at the code level.
2. **Rate Limiter** — Per-host request pacing prevents target overload (configurable recon/test RPS).
3. **Circuit Breaker** — Automatically stops requests to dead or WAF-blocked hosts.
4. **Exploitation Gate** (`exploit.py`) — The `_EXPLOITATION_APPROVED` flag can **only** be set by `chat.py` after the user types explicit confirmation. The LLM has no tool to modify this flag.

```
Agent: "I've identified 3 injection points. Shall I proceed with exploitation testing?"
                              │
                    ┌─────────▼───────────┐
                    │  User types "yes"   │  ← ONLY way to unlock
                    └─────────┬───────────┘
                              │
                    ┌─────────▼───────────┐
                    │  chat.py calls      │
                    │  approve_exploit()  │
                    └─────────┬───────────┘
                              │
                    ┌─────────▼───────────┐
                    │  Payloads fire      │
                    └─────────────────────┘
```

---

## Interfaces

X5Sentry v5.0 provides three interface modes:

### 1. Interactive Chat Console (Default)

Rich-styled terminal chat with the AI agent. Supports natural language, slash commands, and real-time tool execution display.

```bash
xssentry https://target.com
```

**Console commands:**
| Command | Description |
|---|---|
| `/target <url>` | Set or change the target URL |
| `/status` | Show current scan state |
| `/help` | Display available commands |
| `exit` / `quit` | Exit the console |

### 2. Web Dashboard

Modern cyberpunk SPA with real-time SSE streaming of AI reasoning and tool execution.

```bash
xssentry --app
xssentry --app --port 9090
xssentry --web --host 0.0.0.0 --port 8888
```

### 3. Native Desktop Application

PyQt6 WebEngine window embedding the web dashboard (with fallback to standalone app-mode browser).

```bash
xssentry --desktop
xssentry --desktop --port 9090
```

---

## Usage

```bash
xssentry [target] [options]
```

### Core Options

| Flag | Default | Description |
|---|---|---|
| `target` (positional) | — | Target URL (optional — can set via `/target` in console) |
| `--url`, `-u` | — | Target URL (flag alternative) |
| `--api-key`, `-k` | `$NVIDIA_API_KEY` | NVIDIA NIM API key |
| `--model`, `-m` | `nvidia/nemotron-3-super-120b-a12b` | LLM model ID |
| `--max-iterations`, `-i` | `100` | Max agent tool-calling iterations per turn |
| `--verbose`, `-v` | off | Enable debug logging |

### Interface Modes

| Flag | Description |
|---|---|
| `--app` / `--web` | Launch the web dashboard in browser |
| `--desktop` | Launch as native desktop window |
| `--port`, `-p` | Port for web/desktop app (default: 8888) |
| `--host` | Host for web app (default: 127.0.0.1) |

### Examples

```bash
# Interactive chat console — AI agent handles everything
xssentry https://target.com

# Start console without target — set it inside with /target
xssentry

# Use a specific API key and model
xssentry -u https://target.com -k "nvapi-..." -m nvidia/nemotron-3-super-120b-a12b

# Launch the web dashboard
xssentry --app

# Launch as desktop application
xssentry --desktop

# Verbose debug mode
xssentry https://target.com --verbose
```

---

## Reconnaissance Engine — Hellhound Spider

The bundled spider (~9,400 lines) executes the following modules before handing discovered endpoints to the AI agent:

| Module | Capability |
|---|---|
| **Static Crawler** | Multi-threaded async crawl with depth control, domain scoping, and cluster-based deduplication |
| **SPA Scanner** | Extracts routes and parameters from inline JavaScript, `<script>` tags, and framework manifests |
| **Deep SPA Crawler** | Playwright-powered multi-page rendering — clicks interactive elements, harvests dynamic DOM links |
| **Intelligent Prober** | Wordlist-based parameter fuzzing and hidden endpoint brute-forcing |
| **WAF Detector** | Fingerprints WAF/CDN products via response headers and behavior |
| **TLS Inspector** | Analyses certificate chain, expiry, SAN mismatches, and weak cipher suites |
| **Header Auditor** | Evaluates security headers (CSP, HSTS, X-Frame-Options, Permissions-Policy) |
| **DNS Intelligence** | Resolves A/AAAA/CNAME/MX/TXT/NS records; identifies dangling DNS and cloud hosting |
| **WhatWeb Integration** | External WhatWeb fingerprinting with rich tech-stack panel and fallback |
| **Subdomain Enumerator** | Passive subdomain discovery via certificate transparency and DNS brute-forcing |
| **Wayback Probe** | Retrieves historical endpoints from the Wayback Machine CDX API |
| **Robots & Security.txt** | Parses `robots.txt` directives, `security.txt` fields, and flags leaks |
| **HAR Importer** | Ingests browser-recorded HAR files for offline endpoint import |
| **Extractor** | Extracts forms, hidden fields, API routes, inline credentials, CTF flags, and HTML comment leaks |

---

## Requirements

- Python 3.9+
- **NVIDIA NIM API key** ([build.nvidia.com](https://build.nvidia.com/))
- `openai>=1.0.0`, `requests`, `beautifulsoup4`, `lxml`, `rich`, `aiohttp`
- Optional: `playwright` (for browser validation), `PyQt6` (for desktop mode)
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
