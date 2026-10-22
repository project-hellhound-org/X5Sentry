"""
xssentry/llm_brain.py

Central AI Agent — the "Sentry" brain.

Implements the agentic tool-calling loop using NVIDIA's NIM API
(nvidia/nemotron-3-super-120b-a12b) via the OpenAI-compatible client.

Architecture (modeled on bounty-hunter's Agent → ToolSpec → TOOL_REGISTRY):
  1. User message arrives
  2. Build system prompt with target context + tool definitions
  3. Send to LLM with tools registered as OpenAI function-call schemas
  4. If LLM returns tool_calls → execute each tool → feed results back → loop
  5. If LLM returns text → return to user
  6. Max iteration cap prevents runaway loops

The LLM decides WHEN to call tools and WHICH tools to call.
The code just executes what it asks for and enforces safety.
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from openai import OpenAI, APIConnectionError

logger = logging.getLogger("xssentry.llm_brain")


# ═══════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════

DEFAULT_MODEL = "nvidia/nemotron-3-super-120b-a12b"
DEFAULT_BASE_URL = "https://integrate.api.nvidia.com/v1"
MAX_AGENT_ITERATIONS = 100
MAX_HISTORY_TURNS = 14  # sliding window — keep last N messages (optimized for fast context)



# ═══════════════════════════════════════════════════════════════════
# TOOL SPECIFICATION
# ═══════════════════════════════════════════════════════════════════

@dataclass
class ToolSpec:
    """Describes a tool the LLM can invoke."""
    name: str
    description: str
    parameters: Dict[str, Any]          # JSON Schema for function params
    executor: Callable[..., Dict[str, Any]]  # fn(args, context) → result dict


# Global tool registry — modules register themselves here on import
TOOL_REGISTRY: Dict[str, ToolSpec] = {}


def register_tool(spec: ToolSpec) -> None:
    """Register a tool in the global registry."""
    TOOL_REGISTRY[spec.name] = spec
    logger.debug("Registered tool: %s", spec.name)


def _build_openai_tools() -> List[Dict[str, Any]]:
    """Convert TOOL_REGISTRY into OpenAI function-call tool definitions."""
    tools = []
    for name, spec in TOOL_REGISTRY.items():
        tools.append({
            "type": "function",
            "function": {
                "name": spec.name,
                "description": spec.description,
                "parameters": spec.parameters,
            }
        })
    return tools


# ═══════════════════════════════════════════════════════════════════
# SYSTEM PROMPT
# ═══════════════════════════════════════════════════════════════════

def _build_system_prompt(target_url: str, context: Dict[str, Any]) -> str:
    """Build a concise, high-efficiency system prompt for the XSS agent."""
    recon_summary = context.get("recon_summary", "(not yet run)")
    spider_summary = context.get("spider_summary", "(not yet run)")
    findings_summary = context.get("findings_summary", "(none yet)")
    skills_summary = context.get("skills_summary", "(not yet analysed)")

    target_display = target_url if target_url else "(not yet set — user must set using /target <url>)"

    return f"""\
You are SENTRY, an autonomous XSS security testing assistant.
Authorized target: {target_display}

MISSION & WORKFLOW:
1. Recon & Spider: Discover inputs, endpoints, and forms (run_recon, run_spider).
2. Skill Analysis: Call analyse_target_skills to get ranked techniques for this target profile.
3. Payload Selection: Choose context-aware payloads (get_payloads).
4. Confirmation Gate: Before active exploitation, ask: "Shall I proceed with exploitation testing?" and wait for explicit user approval.
5. Exploitation & Evasion: Test approved payloads (test_payload, submit_form); use generate_adaptive_payload if filtered.
6. Persist Novel Skills: Call learn_new_skill if a new bypass pattern is found.

STORED XSS WORKFLOW:
When forms are discovered (especially with fields like 'website', 'url', 'homepage', 'link'):
1. These fields often render into <a href="USER_INPUT"> on the page.
2. Use submit_form to POST the form with javascript:alert(1) in the website/url field.
3. Set check_url to the page where the submitted data is displayed (e.g., the blog post page).
4. If reflection is found in an href attribute, report it as "Stored XSS via href injection".
5. Fill OTHER required fields with realistic data (name, email, comment) so the form submits successfully.

CURRENT STATUS:
• Target: {target_display}
• Recon: {recon_summary}
• Spider: {spider_summary}
• Skills: {skills_summary}
• Findings: {findings_summary}

RULES:
• Scope: NEVER test URLs outside the target domain. If no target is set yet, instruct the user to set one using `/target <url>`.
• Brevity: Keep responses concise, direct, under 150 words. No monologues or filler.
• Safety: Confirmation is required before running test_payload or submit_form.
• Accuracy: If no vulnerability is found, state it clearly. Never fabricate findings.
• JS Strings: If single quotes are escaped with backslash (\\'), inject `\\\\'-alert(1)//` to neutralize the backslash.
• Conversational Queries: When asked general questions (e.g. "what can you do", "who are you", "help"), reply directly and concisely in 2-3 sentences without invoking tools.
"""



# ═══════════════════════════════════════════════════════════════════
# AGENT BRAIN
# ═══════════════════════════════════════════════════════════════════

class AgentBrain:
    """
    The Sentry — XSSentry's AI reasoning engine.

    Manages conversation history, tool dispatch, and the agentic loop
    where the LLM decides what tools to call and when.
    """

    def __init__(
        self,
        target_url: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        max_iterations: int = MAX_AGENT_ITERATIONS,
        on_tool_call: Optional[Callable[[str, Dict], None]] = None,
        on_token: Optional[Callable[[str], None]] = None,
    ):
        self.target_url = target_url or ""
        raw_model = model or os.getenv("NVIDIA_MODEL", DEFAULT_MODEL)
        if raw_model and "/" not in raw_model:
            raw_model = f"nvidia/{raw_model}"
        self.model = raw_model
        self.max_iterations = max_iterations
        self.on_tool_call = on_tool_call   # callback: (tool_name, args) → display
        self.on_token = on_token           # callback: (token) → stream display

        # Context accumulator — tools write their results here
        self.context: Dict[str, Any] = {
            "target_url": target_url,
            "recon_summary": "(not yet run)",
            "spider_summary": "(not yet run)",
            "findings_summary": "(none yet)",
            "recon_data": None,
            "spider_data": None,
            "findings": [],
            "exploitation_approved": False,
        }

        # Conversation history (OpenAI message format)
        self.history: List[Dict[str, Any]] = []

        # OpenAI client pointed at NVIDIA NIM
        resolved_key = api_key or os.getenv("NVIDIA_API_KEY", "")
        if not resolved_key:
            raise ValueError(
                "NVIDIA API key required. Set NVIDIA_API_KEY env var "
                "or pass --api-key to the CLI."
            )

        self.client = OpenAI(
            api_key=resolved_key,
            base_url=base_url or os.getenv("NVIDIA_BASE_URL", DEFAULT_BASE_URL),
        )

        logger.info(
            "AgentBrain initialized — model=%s, target=%s",
            self.model, self.target_url,
        )

    # ──────────────────────────────────────────────────────────────
    # HISTORY MANAGEMENT
    # ──────────────────────────────────────────────────────────────

    def _trim_history(self) -> None:
        """Sliding window: keep only the last MAX_HISTORY_TURNS messages, avoiding orphaned tool messages."""
        if len(self.history) > MAX_HISTORY_TURNS:
            trimmed = self.history[-MAX_HISTORY_TURNS:]
            # Ensure the trimmed window doesn't start on an orphaned tool response
            while trimmed and trimmed[0].get("role") == "tool":
                trimmed = trimmed[1:]
            self.history = trimmed

    def _get_messages(self) -> List[Dict[str, Any]]:
        """Build the full message list: system prompt + conversation history."""
        system_msg = {
            "role": "system",
            "content": _build_system_prompt(self.target_url, self.context),
        }
        self._trim_history()
        return [system_msg] + self.history

    # ──────────────────────────────────────────────────────────────
    # TOOL EXECUTION
    # ──────────────────────────────────────────────────────────────

    def _execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a registered tool and return its result."""
        if tool_name not in TOOL_REGISTRY:
            return {"error": f"Unknown tool: {tool_name}"}

        spec = TOOL_REGISTRY[tool_name]

        # Notify callback if registered
        if self.on_tool_call:
            self.on_tool_call(tool_name, arguments)

        try:
            result = spec.executor(arguments, self.context)

            # Update context based on tool results
            self._update_context(tool_name, result)

            return result

        except Exception as e:
            logger.error("Tool %s failed: %s", tool_name, e, exc_info=True)
            return {"error": f"Tool execution failed: {str(e)}"}

    def _update_context(self, tool_name: str, result: Dict[str, Any]) -> None:
        """Update the agent's context with tool results."""
        if tool_name == "run_recon":
            self.context["recon_data"] = result
            forms_count = len(result.get("forms", []))
            params_count = len(result.get("query_params", []))
            apis_count = len(result.get("api_endpoints", []))
            self.context["recon_summary"] = (
                f"{forms_count} forms, {params_count} query params, "
                f"{apis_count} API endpoints discovered"
            )

        elif tool_name == "run_spider":
            self.context["spider_data"] = result
            pages = result.get("pages_crawled", 0)
            eps = len(result.get("endpoints", []))
            forms = len(result.get("forms", []))
            self.context["spider_summary"] = (
                f"{pages} pages crawled, {eps} endpoints, {forms} forms discovered"
            )

        elif tool_name == "analyse_target_skills":
            self.context["skills_data"] = result
            total = result.get("total_applicable_techniques", 0)
            types = list(result.get("techniques_by_type", {}).keys())
            workflow = result.get("recommended_workflow", [])
            self.context["skills_summary"] = (
                f"{total} techniques applicable across types: {', '.join(types)}. "
                f"Workflow: {'; '.join(workflow[:3])}..."
            )

        elif tool_name == "learn_new_skill":
            if result.get("status") == "created":
                skill_id = result.get("skill_id", "unknown")
                logger.info("New skill learned: %s", skill_id)

        elif tool_name == "test_payload":
            if (result.get("exploitable") or result.get("browser_verified")) and not result.get("error"):
                self.context["findings"].append(result)
                count = len(self.context["findings"])
                self.context["findings_summary"] = (
                    f"{count} confirmed XSS finding(s)"
                )

    # ──────────────────────────────────────────────────────────────
    # AGENTIC LOOP
    # ──────────────────────────────────────────────────────────────

    def handle_message(self, user_text: str) -> str:
        """
        Main agentic loop.

        Sends user message to the LLM with tool definitions.
        If the LLM returns tool_calls, executes them, feeds results back,
        and loops. If the LLM returns text, returns it to the user.

        Returns:
            The LLM's final text response to the user.
        """
        # Add user message to history
        self.history.append({"role": "user", "content": user_text})

        iteration = 0
        final_response = ""

        while iteration < self.max_iterations:
            iteration += 1
            logger.debug("Agent loop iteration %d/%d", iteration, self.max_iterations)

            try:
                # Call the LLM
                messages = self._get_messages()
                tools = _build_openai_tools()

                call_kwargs: Dict[str, Any] = {
                    "model": self.model,
                    "messages": messages,
                    "temperature": 0.3,       # low temp for tool-calling precision
                    "max_tokens": 2048,
                }

                # Only pass tools if we have any registered
                if tools:
                    call_kwargs["tools"] = tools
                    call_kwargs["tool_choice"] = "auto"

                # Always use non-streaming (streaming conflicts with Rich's status spinner)
                response = self._call_non_streaming(call_kwargs)

                if response is None:
                    final_response = "[Agent error: no response from model]"
                    break

                message = response.choices[0].message

                # ── Case 1: LLM wants to call tools ──
                if message.tool_calls:
                    # Add assistant message with tool calls to history
                    self.history.append(self._serialize_assistant_message(message))

                    for tool_call in message.tool_calls:
                        fn_name = tool_call.function.name
                        try:
                            fn_args = json.loads(tool_call.function.arguments)
                        except json.JSONDecodeError:
                            fn_args = {}

                        logger.info("Tool call: %s(%s)", fn_name, json.dumps(fn_args)[:200])

                        # Execute the tool
                        result = self._execute_tool(fn_name, fn_args)

                        # Add tool result to history (compacted to preserve context window & reduce latency)
                        tool_content = json.dumps(result, default=str)
                        if len(tool_content) > 3000:
                            tool_content = tool_content[:3000] + "... [output truncated for context efficiency]"

                        self.history.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": tool_content,
                        })

                    # Loop continues — LLM will see tool results and decide next step
                    continue

                # ── Case 2: LLM returns text (no tool calls) ──
                else:
                    final_response = message.content or ""
                    self.history.append({
                        "role": "assistant",
                        "content": final_response,
                    })
                    break

            except APIConnectionError:
                logger.error("Agent loop error at iteration %d: Connection error.", iteration)
                final_response = "[Agent error: please check your connection]"
                self.history.append({
                    "role": "assistant",
                    "content": final_response,
                })
                break
            except Exception as e:
                logger.error("Agent loop error at iteration %d: %s", iteration, e, exc_info=True)
                final_response = f"[Agent error: {str(e)}]"
                # Add error as assistant message so context isn't lost
                self.history.append({
                    "role": "assistant",
                    "content": final_response,
                })
                break

        # Safety net: if the loop ended but no text response was produced,
        # ensure the user always sees *something* instead of a blank panel.
        if not final_response.strip() and iteration < self.max_iterations:
            logger.warning("Agent loop produced empty final_response after %d iterations.", iteration)
            final_response = (
                "I completed my analysis tools but wasn't able to produce a summary. "
                "Please type **continue** or ask a specific question so I can report my findings."
            )
            self.history.append({
                "role": "assistant",
                "content": final_response,
            })

        if iteration >= self.max_iterations:
            if not final_response:
                try:
                    logger.info("Reached max_iterations (%d). Requesting synthesis summary from LLM.", self.max_iterations)
                    synth_messages = self._get_messages() + [{
                        "role": "user",
                        "content": (
                            f"We have reached the iteration limit ({self.max_iterations}). "
                            "Please provide a comprehensive, detailed summary of all test results so far: "
                            "which endpoints and parameters were tested, which payloads reflected or executed, "
                            "confirmed vulnerabilities, and next recommended steps."
                        ),
                    }]
                    synth_resp = self.client.chat.completions.create(
                        model=self.model,
                        messages=synth_messages,
                        temperature=0.3,
                        max_tokens=1536,
                    )
                    if synth_resp and synth_resp.choices:
                        final_response = synth_resp.choices[0].message.content or ""
                except Exception as e:
                    logger.warning("Failed to get synthesis response after max iterations: %s", e)

            final_response += (
                f"\n\n---\n*⚠️ Batch limit reached ({self.max_iterations} iterations). "
                "Type `continue` to proceed testing or `status` to inspect confirmed findings.*"
            )
            self.history.append({
                "role": "assistant",
                "content": final_response,
            })

        return final_response

    # ──────────────────────────────────────────────────────────────
    # LLM API CALLS
    # ──────────────────────────────────────────────────────────────

    def _call_non_streaming(self, kwargs: Dict[str, Any]):
        """Non-streaming LLM call — used for tool-call loop iterations."""
        try:
            return self.client.chat.completions.create(**kwargs)
        except APIConnectionError:
            logger.error("LLM API call failed: Connection error.")
            raise
        except Exception as e:
            logger.error("LLM API call failed: %s", e)
            raise

    def _call_streaming(self, kwargs: Dict[str, Any]):
        """
        Streaming LLM call — collects tokens via on_token callback.

        Returns a synthetic response object matching non-streaming format
        so the caller doesn't need to branch.
        """
        kwargs["stream"] = True
        collected_content = ""
        collected_tool_calls: List[Dict[str, Any]] = {}
        finish_reason = None

        try:
            stream = self.client.chat.completions.create(**kwargs)

            for chunk in stream:
                delta = chunk.choices[0].delta if chunk.choices else None
                if not delta:
                    continue

                # Collect text tokens
                if delta.content:
                    collected_content += delta.content
                    if self.on_token:
                        self.on_token(delta.content)

                # Collect tool call fragments
                if delta.tool_calls:
                    for tc in delta.tool_calls:
                        idx = tc.index
                        if idx not in collected_tool_calls:
                            collected_tool_calls[idx] = {
                                "id": tc.id or "",
                                "function": {"name": "", "arguments": ""},
                            }
                        if tc.id:
                            collected_tool_calls[idx]["id"] = tc.id
                        if tc.function:
                            if tc.function.name:
                                collected_tool_calls[idx]["function"]["name"] += tc.function.name
                            if tc.function.arguments:
                                collected_tool_calls[idx]["function"]["arguments"] += tc.function.arguments

                if chunk.choices[0].finish_reason:
                    finish_reason = chunk.choices[0].finish_reason

        except APIConnectionError:
            logger.error("Streaming LLM call failed: Connection error.")
            raise
        except Exception as e:
            logger.error("Streaming LLM call failed: %s", e)
            raise

        # Build synthetic response matching non-streaming format
        return _SyntheticResponse(
            content=collected_content,
            tool_calls=collected_tool_calls,
            finish_reason=finish_reason,
        )

    @staticmethod
    def _serialize_assistant_message(message) -> Dict[str, Any]:
        """Serialize an assistant message with tool calls for history storage."""
        msg: Dict[str, Any] = {
            "role": "assistant",
            "content": message.content or "",
        }
        if message.tool_calls:
            msg["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in message.tool_calls
            ]
        return msg

    # ──────────────────────────────────────────────────────────────
    # PUBLIC API
    # ──────────────────────────────────────────────────────────────

    def approve_exploitation(self) -> None:
        """Called by the chat layer when user says 'yes' to exploitation."""
        self.context["exploitation_approved"] = True
        logger.info("User approved exploitation testing")

    def revoke_exploitation(self) -> None:
        """Revoke exploitation approval (safety reset)."""
        self.context["exploitation_approved"] = False
        logger.info("Exploitation approval revoked")

    def is_exploitation_approved(self) -> bool:
        """Check if exploitation has been approved by the user."""
        return self.context.get("exploitation_approved", False)

    def get_findings(self) -> List[Dict[str, Any]]:
        """Return all confirmed findings."""
        return self.context.get("findings", [])

    def set_target(self, target_url: str, guard: Optional[Any] = None) -> None:
        """Update target URL and reset context for the new target."""
        self.target_url = target_url
        self.context["target_url"] = target_url
        if guard is not None:
            self.context["_guard"] = guard
        self.reset_context()

    def reset_context(self) -> None:
        """Reset agent context (keeps history)."""
        self.context.update({
            "target_url": self.target_url,
            "recon_summary": "(not yet run)",
            "spider_summary": "(not yet run)",
            "findings_summary": "(none yet)",
            "recon_data": None,
            "spider_data": None,
            "findings": [],
            "exploitation_approved": False,
        })


# ═══════════════════════════════════════════════════════════════════
# SYNTHETIC RESPONSE (for streaming → non-streaming bridge)
# ═══════════════════════════════════════════════════════════════════

class _SyntheticToolCall:
    """Mimics openai.types.chat.ChatCompletionMessageToolCall."""
    def __init__(self, id: str, name: str, arguments: str):
        self.id = id
        self.type = "function"
        self.function = _SyntheticFunction(name, arguments)


class _SyntheticFunction:
    def __init__(self, name: str, arguments: str):
        self.name = name
        self.arguments = arguments


class _SyntheticMessage:
    """Mimics openai.types.chat.ChatCompletionMessage."""
    def __init__(self, content: str, tool_calls: Optional[List] = None):
        self.content = content
        self.tool_calls = tool_calls
        self.role = "assistant"


class _SyntheticChoice:
    def __init__(self, message: _SyntheticMessage, finish_reason: Optional[str]):
        self.message = message
        self.finish_reason = finish_reason


class _SyntheticResponse:
    """Mimics openai.types.chat.ChatCompletion for the streaming bridge."""
    def __init__(
        self,
        content: str,
        tool_calls: Dict[int, Dict],
        finish_reason: Optional[str],
    ):
        # Build tool call objects if any were collected
        tc_list = None
        if tool_calls:
            tc_list = []
            for idx in sorted(tool_calls.keys()):
                tc_data = tool_calls[idx]
                tc_list.append(_SyntheticToolCall(
                    id=tc_data["id"],
                    name=tc_data["function"]["name"],
                    arguments=tc_data["function"]["arguments"],
                ))

        msg = _SyntheticMessage(content=content, tool_calls=tc_list)
        self.choices = [_SyntheticChoice(message=msg, finish_reason=finish_reason)]
