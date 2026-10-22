"""
xssentry/spider.py

Web spider/crawler — registered as tool 'run_spider' in the LLM brain.

Integrates the full-scale Hellhound Spider (v13.x, ~9,400 lines) for deep,
multi-phase crawling, form detection, API discovery, and parameter mapping.
Falls back gracefully to a built-in BeautifulSoup crawler if the external
engine is unavailable.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import deque
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qs, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from xssentry.llm_brain import ToolSpec, register_tool

logger = logging.getLogger("xssentry.spider")

requests.packages.urllib3.disable_warnings()


# ═══════════════════════════════════════════════════════════════════
# HELLHOUND SPIDER RESOLUTION & INVOCATION
# ═══════════════════════════════════════════════════════════════════

def _find_spider_script() -> Optional[str]:
    """Locate the 9,400-line Hellhound Spider script."""
    candidates = [
        # In current package directory
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "hellhound_spider.py"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "spider.py"),
        # In repository / project root
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "spider.py"),
        # In current working directory
        os.path.join(os.getcwd(), "spider.py"),
    ]

    for p in candidates:
        if os.path.isfile(p) and os.path.getsize(p) > 50000:
            return p

    # Check PATH
    bin_path = shutil.which("spider") or shutil.which("hellhound_spider")
    if bin_path:
        return bin_path

    return None


def run_hellhound_spider(
    target_url: str,
    max_depth: int = 3,
    timeout: int = 15,
    max_runtime: int = 60,
    cookie: Optional[str] = None,
    auth_header: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Execute the full Hellhound Spider against the target and parse the JSON report.
    Returns structured endpoints, forms, parameters, and agent targets.
    """
    spider_path = _find_spider_script()
    if not spider_path:
        logger.warning("Hellhound Spider script not found; falling back to internal crawler.")
        return None

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        temp_json = f.name

    cmd = [
        sys.executable,
        spider_path,
        target_url,
        "--out", temp_json,
        "--format", "json",
        "--depth", str(max_depth),
        "--timeout", str(timeout),
        "--max-runtime", str(max_runtime),
        "--no-playwright",
    ]

    if cookie:
        cmd.extend(["--cookie", cookie])
    if auth_header:
        cmd.extend(["--auth", auth_header])

    logger.info("Executing Hellhound Spider (%d lines): %s", os.path.getsize(spider_path), " ".join(cmd[:6]))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max_runtime + 30,
            cwd=os.path.dirname(spider_path),
        )

        if not os.path.exists(temp_json) or os.path.getsize(temp_json) == 0:
            logger.warning("Hellhound Spider did not generate output JSON: %s", proc.stderr[:300])
            return None

        with open(temp_json, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)

        try:
            os.remove(temp_json)
        except OSError:
            pass

        # Normalize endpoints and parameters from Hellhound Spider report
        raw_eps = data.get("endpoints", [])
        agent_targets = data.get("agent_targets", [])
        summary = data.get("summary", {})

        all_endpoints = []
        all_params = []
        all_forms = []

        seen_eps = set()

        for ep in raw_eps:
            url = ep.get("url", "")
            if not url:
                continue

            # Method resolution
            method_raw = ep.get("method") or ep.get("methods")
            if isinstance(method_raw, list) and method_raw:
                methods = [m.upper() for m in method_raw]
            elif isinstance(method_raw, str):
                methods = [method_raw.upper()]
            else:
                methods = ["GET"]

            # Parameter resolution
            p_raw = ep.get("params", [])
            p_detail = ep.get("params_detail", {})
            params = {}

            if isinstance(p_raw, list):
                for p in p_raw:
                    params[p] = "test"
            elif isinstance(p_raw, dict):
                for bucket in ["query", "form", "js", "openapi", "runtime"]:
                    for p in p_raw.get(bucket, []):
                        params[p] = "test"

            if not params and isinstance(p_detail, dict):
                for bucket in ["query", "form", "js", "openapi", "runtime"]:
                    for p in p_detail.get(bucket, []):
                        params[p] = "test"

            # Form fields
            form_fields_detail = ep.get("form_fields_detail", [])
            hidden = {}
            inputs = []
            for ff in form_fields_detail:
                if isinstance(ff, dict):
                    name = ff.get("name", "")
                    val = ff.get("value", "")
                    ftype = ff.get("type", "").lower()
                    if name:
                        inputs.append({"name": name, "type": ftype or "text", "value": val})
                        if ftype in ("hidden", "csrf"):
                            hidden[name] = val

            for m in methods:
                ep_key = f"{m}:{url}"
                if ep_key not in seen_eps:
                    seen_eps.add(ep_key)
                    all_endpoints.append({
                        "url": url,
                        "method": m,
                        "params": params,
                        "hidden": hidden,
                        "source": "hellhound_spider",
                    })

                # Register parameters
                for param_name in params:
                    all_params.append({
                        "name": param_name,
                        "endpoint": url,
                        "method": m,
                        "type": "query" if m == "GET" else "form",
                    })

                # Register forms if form parameters or POST
                if m == "POST" or inputs:
                    all_forms.append({
                        "action": url,
                        "method": m,
                        "inputs": inputs or [{"name": p, "type": "text"} for p in params],
                        "hidden": hidden,
                        "source": "hellhound_spider",
                    })

        return {
            "engine": "hellhound_spider",
            "start_url": target_url,
            "pages_crawled": summary.get("total_endpoints", len(all_endpoints)),
            "endpoints": all_endpoints,
            "agent_targets": agent_targets,
            "forms": all_forms,
            "parameters": all_params,
            "summary": summary,
            "tech_stack": data.get("tech_stack", []),
            "total_endpoints": len(all_endpoints),
            "total_forms": len(all_forms),
            "total_parameters": len(all_params),
        }

    except Exception as e:
        logger.error("Failed to run Hellhound Spider: %s", e, exc_info=True)
        if os.path.exists(temp_json):
            try:
                os.remove(temp_json)
            except OSError:
                pass
        return None


# ═══════════════════════════════════════════════════════════════════
# FALLBACK INTERNAL CRAWLER
# ═══════════════════════════════════════════════════════════════════

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wmv",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".map", ".min.js",
}


def _is_same_origin(url: str, target_host: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    return host == target_host or host.endswith(f".{target_host}")


def _should_skip(url: str) -> bool:
    parsed = urlparse(url)
    path_lower = parsed.path.lower()
    return any(path_lower.endswith(ext) for ext in SKIP_EXTENSIONS)


def _extract_links(soup: BeautifulSoup, base_url: str, target_host: str) -> List[str]:
    links = []
    for tag in soup.find_all(["a", "area"], href=True):
        href = urljoin(base_url, tag["href"]).split("#")[0]
        if href and _is_same_origin(href, target_host) and not _should_skip(href):
            links.append(href)
    for form in soup.find_all("form", action=True):
        action = urljoin(base_url, form["action"]).split("#")[0]
        if action and _is_same_origin(action, target_host):
            links.append(action)
    return links


def _extract_forms_from_page(soup: BeautifulSoup, page_url: str) -> List[Dict[str, Any]]:
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        action = urljoin(page_url, action) if action else page_url
        method = (form.get("method") or "GET").upper()

        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                inputs.append({
                    "name": name,
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                })

        forms.append({
            "action": action,
            "method": method,
            "inputs": inputs,
            "id": form.get("id", ""),
            "name": form.get("name", ""),
        })
    return forms


def _fallback_crawl(
    start_url: str,
    max_depth: int = 3,
    max_pages: int = 50,
    delay: float = 0.1,
    timeout: int = 15,
) -> Dict[str, Any]:
    """Lightweight fallback crawler using requests + BeautifulSoup."""
    parsed_start = urlparse(start_url)
    target_host = (parsed_start.hostname or "").lower()

    visited: Set[str] = set()
    queue: deque = deque()
    queue.append((start_url, 0))

    all_forms: List[Dict] = []
    all_params: List[Dict] = []
    all_endpoints: List[Dict] = []
    pages_crawled = 0

    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    session.verify = False

    while queue and pages_crawled < max_pages:
        url, depth = queue.popleft()
        url = url.split("#")[0].rstrip("/")
        if url in visited or depth > max_depth or _should_skip(url):
            continue
        visited.add(url)

        try:
            time.sleep(delay)
            resp = session.get(url, timeout=timeout, allow_redirects=True)
            pages_crawled += 1

            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type.lower():
                continue

            soup = BeautifulSoup(resp.text, "html.parser")
            forms = _extract_forms_from_page(soup, resp.url)
            all_forms.extend(forms)

            # Query params
            parsed_q = parse_qs(urlparse(resp.url).query)
            for param_name, vals in parsed_q.items():
                all_params.append({
                    "name": param_name,
                    "endpoint": resp.url.split("?")[0],
                    "method": "GET",
                    "sample_value": vals[0] if vals else "",
                })

            all_endpoints.append({
                "url": resp.url,
                "method": "GET",
                "params": {k: "test" for k in parsed_q},
                "source": "fallback_spider",
            })

            if depth < max_depth:
                for link in _extract_links(soup, resp.url, target_host):
                    norm = link.split("#")[0].rstrip("/")
                    if norm not in visited:
                        queue.append((link, depth + 1))

        except Exception as e:
            logger.debug("Fallback crawler error on %s: %s", url, e)
            continue

    return {
        "engine": "fallback_crawler",
        "start_url": start_url,
        "pages_crawled": pages_crawled,
        "endpoints": all_endpoints,
        "agent_targets": [],
        "forms": all_forms,
        "parameters": all_params,
        "total_endpoints": len(all_endpoints),
        "total_forms": len(all_forms),
        "total_parameters": len(all_params),
    }


def crawl(
    start_url: str,
    max_depth: int = 3,
    max_pages: int = 50,
    delay: float = 0.1,
    timeout: int = 15,
    cookie: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Main entry point for crawling. Always attempts the full Hellhound Spider first.
    """
    # 1. Primary engine: Hellhound Spider
    result = run_hellhound_spider(
        target_url=start_url,
        max_depth=max_depth,
        timeout=timeout,
        cookie=cookie,
    )
    if result is not None:
        return result

    # 2. Fallback engine
    return _fallback_crawl(start_url, max_depth=max_depth, max_pages=max_pages, delay=delay, timeout=timeout)


# ═══════════════════════════════════════════════════════════════════
# TOOL EXECUTOR
# ═══════════════════════════════════════════════════════════════════

def execute_spider(args: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Tool executor for the spider."""
    url = args.get("url") or context.get("target_url", "")
    max_depth = args.get("max_depth", 3)
    max_pages = args.get("max_pages", 50)
    cookie = args.get("cookie") or context.get("cookie")

    if not url:
        return {"error": "No URL provided for spidering"}

    # Scope check
    guard = context.get("_guard")
    if guard:
        check = guard.pre_request(url, is_recon=True)
        if not check["allowed"]:
            return {"error": f"Scope violation: {check['reason']}"}

    return crawl(url, max_depth=max_depth, max_pages=max_pages, cookie=cookie)


# ═══════════════════════════════════════════════════════════════════
# TOOL REGISTRATION
# ═══════════════════════════════════════════════════════════════════

_SPIDER_TOOL = ToolSpec(
    name="run_spider",
    description=(
        "Run the full Hellhound Spider engine (~9,400 lines) to deeply crawl "
        "and discover all endpoints, forms, hidden parameters, and attack surface. "
        "Always run this during autonomous discovery to find actionable XSS injection vectors."
    ),
    parameters={
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "The target URL to crawl.",
            },
            "max_depth": {
                "type": "integer",
                "description": "Maximum crawl depth (default: 3).",
            },
            "max_pages": {
                "type": "integer",
                "description": "Maximum pages to crawl (default: 50).",
            },
            "cookie": {
                "type": "string",
                "description": "Optional session cookie for authenticated spidering.",
            },
        },
        "required": ["url"],
    },
    executor=execute_spider,
)

register_tool(_SPIDER_TOOL)
