"""
xssentry/form_submit.py

Form submission engine — registered as tool 'submit_form' in the LLM brain.

Enables the agent to:
  - Submit HTML forms via POST (e.g., post a comment with a payload)
  - Auto-extract CSRF tokens from the form page
  - Verify stored reflection by fetching the page where submitted data is displayed
  - Detect href/src attribute injection context specifically

This is critical for Stored XSS testing where the payload must be
submitted via a form and then verified on a separate page.
"""

import html
import logging
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from xssentry.llm_brain import ToolSpec, register_tool

logger = logging.getLogger("xssentry.form_submit")

requests.packages.urllib3.disable_warnings()

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


# ═══════════════════════════════════════════════════════════════════
# FORM DISCOVERY & CSRF EXTRACTION
# ═══════════════════════════════════════════════════════════════════

def _fetch_form_page(url: str, session: requests.Session) -> Dict[str, Any]:
    """Fetch a page and extract all forms with their fields."""
    try:
        resp = session.get(url, timeout=15, verify=False, allow_redirects=True)
        soup = BeautifulSoup(resp.text, "html.parser")

        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            action = urljoin(resp.url, action) if action else resp.url
            method = (form.get("method") or "GET").upper()

            fields = {}
            field_details = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                if not name:
                    continue
                value = inp.get("value", "")
                input_type = inp.get("type", "text").lower()

                fields[name] = value
                field_details.append({
                    "name": name,
                    "type": input_type,
                    "value": value,
                    "placeholder": inp.get("placeholder", ""),
                    "required": inp.has_attr("required"),
                })

            forms.append({
                "action": action,
                "method": method,
                "fields": fields,
                "field_details": field_details,
            })

        return {
            "url": resp.url,
            "status_code": resp.status_code,
            "forms": forms,
            "cookies": dict(resp.cookies),
        }
    except requests.RequestException as e:
        return {"error": str(e), "url": url}


def _extract_csrf_token(fields: Dict[str, str]) -> Dict[str, str]:
    """Identify and return CSRF-like hidden fields."""
    csrf_names = {"csrf", "csrftoken", "csrf_token", "_csrf", "token",
                  "_token", "authenticity_token", "nonce", "__RequestVerificationToken"}
    csrf_fields = {}
    for name, value in fields.items():
        if name.lower() in csrf_names or "csrf" in name.lower() or "token" in name.lower():
            csrf_fields[name] = value
    return csrf_fields


# ═══════════════════════════════════════════════════════════════════
# STORED REFLECTION VERIFICATION
# ═══════════════════════════════════════════════════════════════════

def _check_stored_reflection(
    check_url: str,
    payload: str,
    target_field: str,
    session: requests.Session,
) -> Dict[str, Any]:
    """
    Fetch the check_url and verify if the payload appears in the response.
    Returns detailed analysis of where/how the payload is reflected.
    """
    try:
        resp = session.get(check_url, timeout=15, verify=False, allow_redirects=True)
        body = resp.text
        lower_body = body.lower()
        lower_payload = payload.lower()

        result = {
            "check_url": check_url,
            "status_code": resp.status_code,
            "payload_found": False,
            "reflection_context": "not_found",
            "exact_match": False,
            "html_encoded": False,
            "href_injection": False,
            "stored_xss": False,
            "exploitable": False,
            "notes": [],
        }

        # Check exact payload reflection
        if payload in body:
            result["payload_found"] = True
            result["exact_match"] = True

            # Determine context
            idx = body.find(payload)
            before = body[max(0, idx - 300):idx]
            after = body[idx + len(payload):idx + len(payload) + 200]
            before_lower = before.lower()

            # Check specifically for href attribute context
            for attr in ("href", "src", "action", "formaction"):
                for quote in ('"', "'"):
                    pattern = f'{attr}={quote}'
                    attr_idx = before_lower.rfind(pattern)
                    if attr_idx > -1:
                        # Verify the attribute is still open (no closing quote between attr and payload)
                        after_pattern = before[attr_idx + len(pattern):]
                        if quote not in after_pattern:
                            result["reflection_context"] = f"{attr}_attribute"
                            result["href_injection"] = (attr == "href")

                            # Check if javascript: protocol is in the payload
                            if lower_payload.strip().startswith("javascript:"):
                                result["stored_xss"] = True
                                result["exploitable"] = True
                                result["notes"].append(
                                    f"STORED XSS CONFIRMED: javascript: protocol injected into "
                                    f"<a {attr}=\"{payload}\"> — triggers when user clicks the link!"
                                )
                            elif lower_payload.strip().startswith("data:"):
                                result["stored_xss"] = True
                                result["exploitable"] = True
                                result["notes"].append(
                                    f"STORED XSS: data: URI injected into {attr} attribute"
                                )
                            else:
                                result["notes"].append(
                                    f"Payload reflected in {attr} attribute. "
                                    f"Try javascript:alert(1) to exploit."
                                )
                            break
                if result["reflection_context"] != "not_found":
                    break

            # If not in href/src, check other contexts
            if result["reflection_context"] == "not_found":
                # Check script context
                script_open = before.rfind("<script")
                script_close = before.rfind("</script")
                if script_open > script_close:
                    result["reflection_context"] = "script_block"
                    result["stored_xss"] = True
                    result["exploitable"] = True
                    result["notes"].append("Payload persisted inside <script> block!")

                # Check generic attribute
                elif '="' in before[-50:] or "='" in before[-50:]:
                    result["reflection_context"] = "attribute_value"
                    result["notes"].append("Payload reflected in HTML attribute value")

                # HTML body
                else:
                    result["reflection_context"] = "html_body"
                    # Check if it contains active elements
                    if any(tag in lower_payload for tag in ("<script", "<img", "<svg", "onerror", "onload")):
                        result["stored_xss"] = True
                        result["exploitable"] = True
                        result["notes"].append("Payload with active elements persisted in HTML body!")
                    else:
                        result["notes"].append("Payload reflected in HTML body (text context)")

        # Check HTML-entity encoded reflection
        elif html.escape(payload) in body:
            result["payload_found"] = True
            result["html_encoded"] = True
            result["notes"].append(
                "Payload reflected with HTML entity encoding — XSS blocked by output encoding"
            )

        # Check partial (URL-encoded or stripped)
        elif lower_payload in lower_body:
            result["payload_found"] = True
            result["notes"].append("Payload reflected (case-insensitive match)")

        else:
            result["notes"].append(
                f"Payload not found on {check_url}. "
                "The submission may not have persisted, or it renders on a different page."
            )

        return result

    except requests.RequestException as e:
        return {
            "check_url": check_url,
            "error": f"Failed to fetch check_url: {str(e)}",
            "payload_found": False,
        }


# ═══════════════════════════════════════════════════════════════════
# TOOL EXECUTOR
# ═══════════════════════════════════════════════════════════════════

def execute_submit_form(args: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Submit a form and optionally verify stored reflection.

    Workflow:
    1. Fetch the form page to discover fields and extract CSRF tokens
    2. Merge user-provided fields with auto-discovered defaults
    3. Submit the form via POST
    4. If check_url provided, fetch it to verify stored reflection
    """
    from xssentry.exploit import is_exploitation_approved

    # ═══════ SAFETY GATE ═══════
    if not is_exploitation_approved():
        return {
            "error": "EXPLOITATION NOT APPROVED",
            "message": (
                "You must ask the user 'Shall I proceed with exploitation testing?' "
                "and receive explicit approval before submitting forms with payloads. "
                "The user has NOT yet approved exploitation."
            ),
            "action_required": "Ask user for exploitation approval first",
        }
    # ═══════════════════════════

    form_url = args.get("form_url", "")
    action_url = args.get("action_url", "")
    fields = args.get("fields", {})
    check_url = args.get("check_url", "")
    target_field = args.get("target_field", "")

    if not form_url and not action_url:
        return {"error": "Must provide form_url or action_url"}

    if not fields:
        return {"error": "Must provide fields dict with form field values"}

    # Scope check
    guard = context.get("_guard")
    for url_to_check in [form_url, action_url, check_url]:
        if url_to_check and guard:
            check = guard.pre_request(url_to_check, is_recon=False)
            if not check["allowed"]:
                return {"error": f"Scope violation: {check['reason']}"}

    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    # Step 1: Fetch the form page for CSRF tokens and default field values
    form_data = {}
    if form_url:
        logger.info("Fetching form page: %s", form_url)
        page_info = _fetch_form_page(form_url, session)

        if "error" in page_info:
            return {"error": f"Failed to fetch form page: {page_info['error']}"}

        # Auto-fill CSRF tokens and hidden fields from the first matching form
        for discovered_form in page_info.get("forms", []):
            if discovered_form["method"] == "POST":
                # Start with the discovered form's default field values
                form_data = dict(discovered_form["fields"])
                # Extract CSRF tokens
                csrf = _extract_csrf_token(form_data)
                if csrf:
                    logger.info("Auto-extracted CSRF tokens: %s", list(csrf.keys()))
                # If no action_url provided, use the form's action
                if not action_url:
                    action_url = discovered_form["action"]
                break

    if not action_url:
        action_url = form_url

    # Step 2: Merge user-provided fields (override auto-discovered ones)
    form_data.update(fields)

    # Identify the payload being tested
    payload_value = fields.get(target_field, "") if target_field else ""
    if not payload_value:
        # Pick the first non-CSRF, non-hidden field value as the "payload"
        csrf_keys = _extract_csrf_token(form_data).keys()
        for k, v in fields.items():
            if k not in csrf_keys and v:
                payload_value = v
                if not target_field:
                    target_field = k
                break

    logger.info(
        "Submitting form to %s with %d fields (target_field=%s)",
        action_url, len(form_data), target_field,
    )

    # Step 3: Submit the form
    try:
        resp = session.post(
            action_url,
            data=form_data,
            timeout=15,
            verify=False,
            allow_redirects=True,
        )

        result = {
            "submitted": True,
            "action_url": action_url,
            "method": "POST",
            "status_code": resp.status_code,
            "redirect_url": resp.url if resp.url != action_url else None,
            "fields_submitted": list(form_data.keys()),
            "target_field": target_field,
            "payload": payload_value,
        }

        # Step 4: Verify stored reflection if check_url provided
        if check_url and payload_value:
            logger.info("Checking stored reflection at: %s", check_url)
            time.sleep(0.5)  # Brief pause for server-side persistence
            reflection = _check_stored_reflection(
                check_url=check_url,
                payload=payload_value,
                target_field=target_field,
                session=session,
            )
            result["stored_reflection"] = reflection

            if reflection.get("stored_xss"):
                result["vulnerability_confirmed"] = True
                result["vulnerability_type"] = "Stored XSS"
                result["severity"] = "HIGH"

                if reflection.get("href_injection"):
                    result["vulnerability_type"] = "Stored XSS via href injection"
                    result["trigger"] = (
                        f"User clicks the link containing the injected payload on {check_url}"
                    )
                elif reflection.get("reflection_context") == "script_block":
                    result["trigger"] = f"Payload executes automatically when visiting {check_url}"
                elif reflection.get("reflection_context") == "html_body":
                    result["trigger"] = f"Payload executes automatically when visiting {check_url}"

        if guard:
            guard.record_success(action_url)

        return result

    except requests.RequestException as e:
        if guard:
            guard.record_failure(action_url)
        return {
            "error": f"Form submission failed: {str(e)}",
            "action_url": action_url,
            "target_field": target_field,
        }


# ═══════════════════════════════════════════════════════════════════
# TOOL REGISTRATION
# ═══════════════════════════════════════════════════════════════════

_SUBMIT_FORM_TOOL = ToolSpec(
    name="submit_form",
    description=(
        "Submit an HTML form via POST to test for Stored XSS. "
        "Fetches the form page to auto-extract CSRF tokens and hidden fields, "
        "then submits the form with the provided field values. "
        "Use 'check_url' to verify if the submitted payload persists on another page. "
        "This is essential for testing Stored XSS where the payload is submitted "
        "via a form (e.g., comment, profile, feedback) and rendered elsewhere. "
        "For href injection: use javascript:alert(1) as the payload in 'website' "
        "or 'url' form fields — it gets stored in <a href='...'> attributes. "
        "IMPORTANT: Requires exploitation approval from the user."
    ),
    parameters={
        "type": "object",
        "properties": {
            "form_url": {
                "type": "string",
                "description": (
                    "URL of the page containing the form. "
                    "The tool will fetch this page to discover CSRF tokens and default field values."
                ),
            },
            "action_url": {
                "type": "string",
                "description": (
                    "The form's action URL (where the POST is sent). "
                    "If omitted, auto-detected from the form on form_url."
                ),
            },
            "fields": {
                "type": "object",
                "description": (
                    "Field name -> value mapping for the form submission. "
                    "Example: {\"comment\": \"Great post!\", \"name\": \"tester\", "
                    "\"website\": \"javascript:alert(1)\", \"email\": \"test@test.com\"}"
                ),
            },
            "check_url": {
                "type": "string",
                "description": (
                    "URL to verify stored reflection after submission. "
                    "For blog comments, this is the blog post URL where comments are displayed."
                ),
            },
            "target_field": {
                "type": "string",
                "description": (
                    "The specific field name being tested for XSS injection "
                    "(e.g., 'website', 'comment', 'name'). Used for focused reflection analysis."
                ),
            },
        },
        "required": ["fields"],
    },
    executor=execute_submit_form,
)

register_tool(_SUBMIT_FORM_TOOL)
