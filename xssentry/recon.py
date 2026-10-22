"""
xssentry/recon.py

Reconnaissance engine — registered as tool 'run_recon' in the LLM brain.

Performs curl-style HTTP fetch + HTML analysis to discover:
  - HTML forms (action, method, input fields)
  - URL query parameters
  - JSON/API endpoints (from script tags, fetch patterns, Content-Type)
  - Response fingerprinting (server headers, CSP, security headers)
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urljoin

import requests
from bs4 import BeautifulSoup

from xssentry.llm_brain import ToolSpec, register_tool

logger = logging.getLogger("xssentry.recon")

# Suppress noisy SSL warnings for testing targets
requests.packages.urllib3.disable_warnings()

# ═══════════════════════════════════════════════════════════════════
# RECON CORE
# ═══════════════════════════════════════════════════════════════════

def _fetch_page(url: str, timeout: int = 15) -> Dict[str, Any]:
    """Fetch a page and return response data."""
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                              "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            },
        )
        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text,
            "url": resp.url,  # after redirects
            "content_type": resp.headers.get("Content-Type", ""),
        }
    except requests.RequestException as e:
        return {"error": str(e), "url": url}


def _extract_forms(soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
    """Extract all HTML forms and their input fields."""
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        if action:
            action = urljoin(base_url, action)
        else:
            action = base_url

        method = (form.get("method") or "GET").upper()
        enctype = form.get("enctype", "application/x-www-form-urlencoded")

        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            input_data = {
                "tag": inp.name,
                "name": inp.get("name", ""),
                "type": inp.get("type", "text"),
                "value": inp.get("value", ""),
                "id": inp.get("id", ""),
                "placeholder": inp.get("placeholder", ""),
            }
            if inp.name == "select":
                input_data["options"] = [
                    opt.get("value", opt.text.strip())
                    for opt in inp.find_all("option")
                ]
            inputs.append(input_data)

        # Only include forms with at least one named input
        named_inputs = [i for i in inputs if i.get("name")]
        if named_inputs:
            forms.append({
                "action": action,
                "method": method,
                "enctype": enctype,
                "inputs": named_inputs,
            })

    return forms


def _extract_query_params(url: str, soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
    """Extract query parameters from the target URL and all linked URLs."""
    params_found = []
    seen = set()

    # From the target URL itself
    parsed = urlparse(url)
    for param, values in parse_qs(parsed.query).items():
        key = f"{parsed.path}:{param}"
        if key not in seen:
            seen.add(key)
            params_found.append({
                "url": url,
                "param": param,
                "sample_value": values[0] if values else "",
                "source": "target_url",
            })

    # From linked pages on the same page
    for a_tag in soup.find_all("a", href=True):
        href = urljoin(base_url, a_tag["href"])
        href_parsed = urlparse(href)

        # Only same-origin links
        base_parsed = urlparse(base_url)
        if href_parsed.hostname != base_parsed.hostname:
            continue

        for param, values in parse_qs(href_parsed.query).items():
            key = f"{href_parsed.path}:{param}"
            if key not in seen:
                seen.add(key)
                params_found.append({
                    "url": href,
                    "param": param,
                    "sample_value": values[0] if values else "",
                    "source": "linked_page",
                })

    return params_found


def _extract_api_endpoints(soup: BeautifulSoup, body: str, base_url: str) -> List[Dict[str, Any]]:
    """Detect potential API/JSON endpoints from script analysis."""
    endpoints = []
    seen = set()

    # Patterns that indicate API calls in JavaScript
    api_patterns = [
        # fetch/XHR calls
        r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['"](\/[^'"]+)['"]""",
        # jQuery AJAX
        r"""(?:\$\.(?:ajax|get|post|getJSON))\s*\(\s*['"](\/[^'"]+)['"]""",
        # URL assignments that look like API endpoints
        r"""(?:url|endpoint|api_url|apiUrl|baseUrl|base_url)\s*[:=]\s*['"](\/api[^'"]+)['"]""",
        # REST-style paths in strings
        r"""['"](\/(api|v[0-9]+|graphql|rest|json)[^'"]{2,})['"]""",
    ]

    for script in soup.find_all("script"):
        script_text = script.string or ""
        for pattern in api_patterns:
            for match in re.finditer(pattern, script_text, re.IGNORECASE):
                path = match.group(1)
                full_url = urljoin(base_url, path)
                if full_url not in seen:
                    seen.add(full_url)
                    endpoints.append({
                        "url": full_url,
                        "source": "javascript",
                        "pattern_matched": pattern[:50],
                    })

    # Also check inline scripts in the full body
    for pattern in api_patterns:
        for match in re.finditer(pattern, body, re.IGNORECASE):
            path = match.group(1)
            full_url = urljoin(base_url, path)
            if full_url not in seen:
                seen.add(full_url)
                endpoints.append({
                    "url": full_url,
                    "source": "inline_body",
                    "pattern_matched": pattern[:50],
                })

    return endpoints


def _fingerprint_response(headers: Dict[str, str]) -> Dict[str, Any]:
    """Fingerprint the response: security headers, server info, framework hints."""
    fp: Dict[str, Any] = {}

    # Server identification
    fp["server"] = headers.get("Server", "unknown")
    fp["powered_by"] = headers.get("X-Powered-By", "unknown")

    # Security headers (relevant for XSS)
    security = {}
    security["csp"] = headers.get("Content-Security-Policy", "MISSING")
    security["x_xss_protection"] = headers.get("X-XSS-Protection", "MISSING")
    security["x_content_type_options"] = headers.get("X-Content-Type-Options", "MISSING")
    security["x_frame_options"] = headers.get("X-Frame-Options", "MISSING")
    security["strict_transport"] = headers.get("Strict-Transport-Security", "MISSING")
    security["referrer_policy"] = headers.get("Referrer-Policy", "MISSING")
    fp["security_headers"] = security

    # Count missing security headers
    missing = sum(1 for v in security.values() if v == "MISSING")
    fp["missing_security_headers"] = missing
    fp["security_posture"] = (
        "weak" if missing >= 4 else "moderate" if missing >= 2 else "strong"
    )

    return fp


# ═══════════════════════════════════════════════════════════════════
# TOOL EXECUTOR
# ═══════════════════════════════════════════════════════════════════

def execute_recon(args: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run reconnaissance on the target URL.

    Discovers input fields, query params, API endpoints, and fingerprints the response.
    """
    url = args.get("url") or context.get("target_url", "")
    if not url:
        return {"error": "No URL provided for recon"}

    # Scope check (if guard is in context)
    guard = context.get("_guard")
    if guard:
        check = guard.pre_request(url, is_recon=True)
        if not check["allowed"]:
            return {"error": f"Scope violation: {check['reason']}"}

    logger.info("Running recon on: %s", url)

    # Fetch the page
    page_data = _fetch_page(url)
    if "error" in page_data:
        return {"error": f"Failed to fetch target: {page_data['error']}", "url": url}

    body = page_data["body"]
    headers = page_data["headers"]
    final_url = page_data["url"]

    # Parse HTML
    soup = BeautifulSoup(body, "html.parser")

    # Extract everything
    forms = _extract_forms(soup, final_url)
    query_params = _extract_query_params(url, soup, final_url)
    api_endpoints = _extract_api_endpoints(soup, body, final_url)
    fingerprint = _fingerprint_response(headers)

    total_inputs = (
        sum(len(f.get("inputs", [])) for f in forms)
        + len(query_params)
        + len(api_endpoints)
    )

    result = {
        "url": final_url,
        "status_code": page_data["status_code"],
        "content_type": page_data["content_type"],
        "forms": forms,
        "query_params": query_params,
        "api_endpoints": api_endpoints,
        "fingerprint": fingerprint,
        "total_input_fields": total_inputs,
        "needs_spider": total_inputs == 0,
    }

    if guard:
        guard.record_success(url)

    logger.info(
        "Recon complete: %d forms, %d params, %d APIs, posture=%s",
        len(forms), len(query_params), len(api_endpoints),
        fingerprint.get("security_posture", "unknown"),
    )

    return result


# ═══════════════════════════════════════════════════════════════════
# TOOL REGISTRATION
# ═══════════════════════════════════════════════════════════════════

_RECON_TOOL = ToolSpec(
    name="run_recon",
    description=(
        "Run reconnaissance on the target URL. Fetches the page, discovers HTML forms "
        "and their input fields, extracts URL query parameters, detects API/JSON endpoints "
        "from JavaScript, and fingerprints security headers. Returns structured JSON with "
        "all discovered input vectors and the target's security posture. Call this FIRST "
        "before any other tool."
    ),
    parameters={
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "The URL to reconnoiter. Must be the authorized target URL or a path under it.",
            },
        },
        "required": ["url"],
    },
    executor=execute_recon,
)

register_tool(_RECON_TOOL)
