"""
xssentry/app.py

Modern Web Application backend for XSSentry.
Provides asynchronous HTTP endpoints, Server-Sent Events (SSE) for
real-time AI reasoning and tool-execution streaming, recon/spider hooks,
and serves the rich cyberpunk Single-Page Web Dashboard.
"""

import asyncio
import json
import logging
import os
import sys
import webbrowser
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from aiohttp import web

from xssentry import __codename__, __version__
from xssentry.guard import XSSentryGuard
from xssentry.llm_brain import (
    TOOL_REGISTRY,
    AgentBrain,
)
# Ensure all tools are imported and registered
import xssentry.recon  # noqa: F401
import xssentry.spider  # noqa: F401
import xssentry.payloads  # noqa: F401
import xssentry.exploit  # noqa: F401
import xssentry.xss_skills  # noqa: F401
import xssentry.form_submit  # noqa: F401

logger = logging.getLogger("xssentry.app")

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")


class AppState:
    """Central state container for the web application session."""

    def __init__(self):
        self.target_url: Optional[str] = None
        self.guard: Optional[XSSentryGuard] = None
        self.brain: Optional[AgentBrain] = None
        self.chat_history: List[Dict[str, Any]] = []
        self.findings: List[Dict[str, Any]] = []
        self.endpoints: List[Dict[str, Any]] = []
        self.forms: List[Dict[str, Any]] = []
        self.live_logs: List[str] = []
        self._init_brain()

    def _init_brain(self):
        try:
            self.brain = AgentBrain()
        except Exception as e:
            logger.warning("Could not initialize AgentBrain: %s", e)
            self.brain = None

    def add_log(self, message: str):
        self.live_logs.append(message)
        if len(self.live_logs) > 500:
            self.live_logs.pop(0)

    def set_target(self, url: str) -> Dict[str, Any]:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed = urlparse(url)
        if not parsed.hostname:
            return {"success": False, "error": "Invalid URL provided."}

        self.target_url = url
        self.guard = XSSentryGuard(url)
        if self.brain:
            self.brain.set_target(url)

        self.add_log(f"🎯 Target set to: {url}")
        return {"success": True, "target": url}


state = AppState()


# ═══════════════════════════════════════════════════════════════════
# API CONTROLLERS
# ═══════════════════════════════════════════════════════════════════

async def api_status(request: web.Request) -> web.Response:
    """Return system, target, and agent health status."""
    return web.json_response({
        "version": __version__,
        "codename": __codename__,
        "target_url": state.target_url,
        "brain_ready": state.brain is not None,
        "tools_count": len(TOOL_REGISTRY),
        "tools": list(TOOL_REGISTRY.keys()),
        "findings_count": len(state.findings),
        "endpoints_count": len(state.endpoints),
        "forms_count": len(state.forms),
    })


async def api_set_target(request: web.Request) -> web.Response:
    """Set active target URL."""
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"success": False, "error": "Invalid JSON body"}, status=400)

    url = data.get("url", "").strip()
    if not url:
        return web.json_response({"success": False, "error": "URL cannot be empty"}, status=400)

    result = state.set_target(url)
    return web.json_response(result)


async def api_get_findings(request: web.Request) -> web.Response:
    """Return all confirmed XSS findings."""
    return web.json_response({"findings": state.findings})


async def api_add_finding(request: web.Request) -> web.Response:
    """Register a new finding manually or from test."""
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"success": False, "error": "Invalid JSON"}, status=400)

    state.findings.append(data)
    state.add_log(f"🔥 New Vulnerability Recorded: {data.get('type', 'XSS')} at {data.get('url')}")
    return web.json_response({"success": True, "total": len(state.findings)})


async def api_get_attack_surface(request: web.Request) -> web.Response:
    """Return discovered endpoints and forms."""
    return web.json_response({
        "endpoints": state.endpoints,
        "forms": state.forms,
    })


async def api_logs(request: web.Request) -> web.Response:
    """Return recent engine logs."""
    return web.json_response({"logs": state.live_logs})


async def api_reset(request: web.Request) -> web.Response:
    """Reset session state."""
    state.chat_history.clear()
    state.findings.clear()
    state.endpoints.clear()
    state.forms.clear()
    state.live_logs.clear()
    state._init_brain()
    if state.target_url and state.brain:
        state.brain.set_target(state.target_url)
    state.add_log("🔄 Session reset.")
    return web.json_response({"success": True})


# ═══════════════════════════════════════════════════════════════════
# STREAMING AI CHAT / AGENT REASONING (SSE)
# ═══════════════════════════════════════════════════════════════════

async def api_chat_stream(request: web.Request) -> web.StreamResponse:
    """
    Server-Sent Events endpoint for real-time AI reasoning.
    Streams thoughts, tool calls, results, and responses.
    """
    response = web.StreamResponse(
        status=200,
        reason="OK",
        headers={
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Access-Control-Allow-Origin": "*",
        },
    )
    await response.prepare(request)

    prompt = request.query.get("prompt", "").strip()
    if not prompt:
        data = json.dumps({"type": "error", "message": "Prompt is required."})
        await response.write(f"data: {data}\n\n".encode("utf-8"))
        await response.write_eof()
        return response

    if not state.brain:
        state._init_brain()
        if not state.brain:
            data = json.dumps({
                "type": "error",
                "message": "AI Brain could not be initialized. Check API keys and network connection.",
            })
            await response.write(f"data: {data}\n\n".encode("utf-8"))
            await response.write_eof()
            return response

    state.add_log(f"💬 User prompt: {prompt[:80]}...")

    # Broadcast event helper
    async def send_event(event_type: str, payload: Dict[str, Any]):
        msg = json.dumps({"type": event_type, **payload})
        try:
            await response.write(f"data: {msg}\n\n".encode("utf-8"))
        except Exception:
            pass

    # Quick slash command handling
    cmd = prompt.strip().split()[0].lower() if prompt.strip() else ""

    if cmd in ("/target", "target"):
        parts = prompt.strip().split(maxsplit=1)
        if len(parts) > 1:
            res = state.set_target(parts[1].strip())
            await send_event("response", {"text": f"🎯 Target updated to `{res.get('target')}`"})
        else:
            await send_event("response", {"text": f"Current target: `{state.target_url or 'None'}`"})
        await send_event("done", {})
        await response.write_eof()
        return response

    if not state.target_url and not any(p.startswith("http") for p in prompt.split()):
        await send_event("response", {
            "text": "⚠️ **No target set.** Please set a target first using `/target <url>` or enter a target URL in the top bar."
        })
        await send_event("done", {})
        await response.write_eof()
        return response

    # Stream agent execution asynchronously in a worker thread/task
    loop = asyncio.get_event_loop()
    queue: asyncio.Queue = asyncio.Queue()

    def run_sync_agent():
        try:
            loop.call_soon_threadsafe(queue.put_nowait, ("status", {"message": "Sentry is analyzing attack vectors..."}))

            # Execute brain query
            agent_res = state.brain.chat(prompt)

            # Check if agent discovered forms or endpoints
            if "submit_form" in str(agent_res):
                state.add_log("⚡ Form audit executed during session")

            loop.call_soon_threadsafe(queue.put_nowait, ("response", {"text": agent_res}))
            loop.call_soon_threadsafe(queue.put_nowait, ("done", {}))
        except Exception as e:
            loop.call_soon_threadsafe(queue.put_nowait, ("error", {"message": str(e)}))
            loop.call_soon_threadsafe(queue.put_nowait, ("done", {}))

    # Run agent in background executor
    asyncio.create_task(asyncio.to_thread(run_sync_agent))

    # Consume queue and stream out to SSE client
    while True:
        try:
            ev_type, ev_data = await asyncio.wait_for(queue.get(), timeout=120.0)
            await send_event(ev_type, ev_data)
            if ev_type == "done":
                break
        except asyncio.TimeoutError:
            await send_event("error", {"message": "Agent request timed out after 120s."})
            break
        except Exception as e:
            logger.error("SSE stream error: %s", e)
            break

    await response.write_eof()
    return response


# ═══════════════════════════════════════════════════════════════════
# QUICK SCAN & FORM ACTION ENDPOINTS
# ═══════════════════════════════════════════════════════════════════

async def api_run_recon(request: web.Request) -> web.Response:
    """Execute quick reconnaissance on the target."""
    if not state.target_url:
        return web.json_response({"success": False, "error": "No target URL set"}, status=400)

    try:
        recon_tool = TOOL_REGISTRY.get("run_recon")
        if not recon_tool:
            return web.json_response({"success": False, "error": "Recon tool not registered"}, status=500)

        state.add_log(f"🔍 Running Recon on {state.target_url}...")
        result = await asyncio.to_thread(recon_tool.func, state.target_url)

        # Cache endpoints
        if isinstance(result, dict) and "endpoints" in result:
            for ep in result.get("endpoints", []):
                if ep not in [e.get("url") for e in state.endpoints]:
                    state.endpoints.append({"url": ep, "method": "GET", "source": "recon"})

        return web.json_response({"success": True, "result": result})
    except Exception as e:
        logger.error("Recon failed: %s", e)
        return web.json_response({"success": False, "error": str(e)}, status=500)


async def api_run_spider(request: web.Request) -> web.Response:
    """Execute crawler/spider on the target."""
    if not state.target_url:
        return web.json_response({"success": False, "error": "No target URL set"}, status=400)

    try:
        spider_tool = TOOL_REGISTRY.get("run_spider")
        if not spider_tool:
            return web.json_response({"success": False, "error": "Spider tool not registered"}, status=500)

        state.add_log(f"🕷️ Running Spider on {state.target_url}...")
        result = await asyncio.to_thread(spider_tool.func, state.target_url, max_pages=15)

        # Parse endpoints and forms from spider output
        if isinstance(result, dict):
            for link in result.get("links", []):
                if link not in [e.get("url") for e in state.endpoints]:
                    state.endpoints.append({"url": link, "method": "GET", "source": "spider"})

            for f in result.get("forms", []):
                state.forms.append(f)

        return web.json_response({"success": True, "result": result})
    except Exception as e:
        logger.error("Spider failed: %s", e)
        return web.json_response({"success": False, "error": str(e)}, status=500)


async def api_submit_form(request: web.Request) -> web.Response:
    """Execute form submission / Stored XSS probe."""
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"success": False, "error": "Invalid JSON"}, status=400)

    url = data.get("url") or state.target_url
    if not url:
        return web.json_response({"success": False, "error": "Target URL required"}, status=400)

    view_url = data.get("view_url")
    field = data.get("field")
    payload = data.get("payload")
    fields = data.get("fields")

    tool = TOOL_REGISTRY.get("submit_form")
    if not tool:
        return web.json_response({"success": False, "error": "submit_form tool not found"}, status=500)

    state.add_log(f"📝 Submitting form on {url} (field={field}, payload={payload})...")
    try:
        kwargs: Dict[str, Any] = {"url": url}
        if view_url:
            kwargs["check_url"] = view_url
        if field:
            kwargs["target_field"] = field
        if payload:
            kwargs["payload"] = payload
        if fields:
            kwargs["fields"] = fields

        result = await asyncio.to_thread(tool.func, **kwargs)

        # Check if stored XSS was confirmed
        if isinstance(result, dict) and (result.get("stored_xss") or result.get("is_vulnerable")):
            finding = {
                "type": "Stored XSS (Cross-Site Scripting)",
                "severity": "High",
                "url": url,
                "view_url": view_url or url,
                "field": field,
                "payload": payload or "javascript:alert(1)",
                "context": result.get("reflection_context", "href_attribute"),
                "notes": result.get("notes", []),
                "verified": True,
            }
            state.findings.append(finding)

        return web.json_response({"success": True, "result": result})
    except Exception as e:
        logger.error("submit_form failed: %s", e)
        return web.json_response({"success": False, "error": str(e)}, status=500)


# ═══════════════════════════════════════════════════════════════════
# APPLICATION FACTORY & RUNNER
# ═══════════════════════════════════════════════════════════════════

def create_app() -> web.Application:
    """Create and configure the aiohttp web application."""
    app = web.Application()

    # API routes
    app.router.add_get("/api/status", api_status)
    app.router.add_post("/api/target", api_set_target)
    app.router.add_get("/api/chat/stream", api_chat_stream)
    app.router.add_get("/api/findings", api_get_findings)
    app.router.add_post("/api/findings", api_add_finding)
    app.router.add_get("/api/attack-surface", api_get_attack_surface)
    app.router.add_get("/api/logs", api_logs)
    app.router.add_post("/api/reset", api_reset)
    app.router.add_post("/api/recon", api_run_recon)
    app.router.add_post("/api/spider", api_run_spider)
    app.router.add_post("/api/submit", api_submit_form)

    # Static files
    if os.path.exists(STATIC_DIR):
        app.router.add_static("/static/", os.path.join(STATIC_DIR, "static"), name="static")

        # Serve index.html for root
        async def index_handler(request: web.Request) -> web.FileResponse:
            return web.FileResponse(os.path.join(STATIC_DIR, "index.html"))

        app.router.add_get("/", index_handler)

    return app


def start_server(host: str = "127.0.0.1", port: int = 8888, open_browser: bool = True):
    """Run the XSSentry web application server."""
    app = create_app()
    url = f"http://{host}:{port}"
    print(f"\n[+] 🚀 XSSentry Web App running at: {url}")
    print("[+] Press Ctrl+C to stop.\n")

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    web.run_app(app, host=host, port=port, print=None)


if __name__ == "__main__":
    start_server()
