"""
xssentry/chat.py

Interactive chat console — Rich-based terminal UI.

Handles:
  - User input/output with styled panels (HELLHOUND-style)
  - The CONFIRMATION GATE: intercepts the agent's exploitation request
    and only approves on explicit "yes" from the user
  - Streams agent responses token-by-token
  - Displays tool call activity with spinners
  - Between steps: user can chat, ask questions, or give commands
"""

import logging
import sys
import time
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from rich.live import Live
from rich.spinner import Spinner
from rich.table import Table
from rich.markdown import Markdown
from rich import box

from xssentry.llm_brain import AgentBrain
from xssentry.guard import XSSentryGuard
from xssentry import exploit

logger = logging.getLogger("xssentry.chat")

# ═══════════════════════════════════════════════════════════════════
# THEME / COLORS
# ═══════════════════════════════════════════════════════════════════

NEON_GREEN = "bright_green"
NEON_CYAN = "bright_cyan"
NEON_RED = "bright_red"
NEON_YELLOW = "bright_yellow"
NEON_MAGENTA = "bright_magenta"
ACCENT = "bright_blue"
DIM = "dim"


# ═══════════════════════════════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════════════════════════════

BANNER = r"""[bright_red]
 ██╗  ██╗███████╗███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
 ╚██╗██╔╝██╔════╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
  ╚███╔╝ ███████╗███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝
  ██╔██╗ ╚════██║╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝
 ██╔╝ ██╗███████║███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║
 ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝[/]
[bright_cyan]          ▀▀ Sentry AI Engine ▀▀  v5.0  [HELLHOUND-class][/]
[dim]     Autonomous XSS Hunter — AI-Powered Tool-Calling Agent[/]
"""


# ═══════════════════════════════════════════════════════════════════
# CONFIRMATION GATE DETECTION
# ═══════════════════════════════════════════════════════════════════

# These must be highly specific — they only match when the agent is explicitly
# requesting user approval to fire XSS payloads, NOT general questions.
_EXPLOIT_QUESTION_MARKERS = [
    "shall i proceed with exploitation",
    "proceed with exploitation testing",
    "begin exploitation testing",
    "start testing payloads",
    "permission to test payloads",
    "launch the payloads",
    "proceed with payload testing",
    "want me to start payload",
    "fire the payloads",
    "shall i proceed with payload",
]


def _is_exploitation_question(text: str) -> bool:
    """Detect if the agent is explicitly requesting exploitation approval."""
    lower = text.lower()
    return any(marker in lower for marker in _EXPLOIT_QUESTION_MARKERS)


# ═══════════════════════════════════════════════════════════════════
# CHAT CONSOLE
# ═══════════════════════════════════════════════════════════════════

class ChatConsole:
    """
    Interactive chat console for XSSentry.

    Manages the conversation loop between the user and the AI agent,
    handles the confirmation gate, and provides styled terminal output.
    """

    def __init__(
        self,
        target_url: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        max_iterations: Optional[int] = None,
    ):
        self.console = Console()
        self.target_url = target_url or ""
        self._streaming_buffer = ""

        # Initialize guard (scope enforcement) if target is provided
        self.guard = XSSentryGuard(self.target_url) if self.target_url else None

        brain_kwargs = {
            "target_url": self.target_url,
            "api_key": api_key,
            "model": model,
            "on_tool_call": self._on_tool_call,
            "on_token": None,
        }
        if max_iterations is not None:
            brain_kwargs["max_iterations"] = max_iterations

        # Initialize the AI brain (no streaming — conflicts with Rich's Live display)
        self.brain = AgentBrain(**brain_kwargs)

        # Inject the guard into the brain's context so tools can access it
        if self.guard:
            self.brain.context["_guard"] = self.guard

    def set_target(self, url: str) -> None:
        """Set or update the target URL and reconfigure guard & brain."""
        self.target_url = url
        self.guard = XSSentryGuard(url)
        self.brain.set_target(url, guard=self.guard)

    # ──────────────────────────────────────────────────────────────
    # CALLBACKS
    # ──────────────────────────────────────────────────────────────

    def _on_tool_call(self, tool_name: str, args: dict) -> None:
        """Called when the agent invokes a tool."""
        # Display tool call with styled indicator
        tool_display = {
            "run_recon": ("🔍", "Reconnaissance", NEON_CYAN),
            "run_spider": ("🕷️", "Spidering", NEON_GREEN),
            "get_payloads": ("💉", "Payload Selection", NEON_YELLOW),
            "generate_adaptive_payload": ("🧬", "Adaptive Payload Gen", NEON_MAGENTA),
            "test_payload": ("⚡", "Exploit Testing", NEON_RED),
        }

        icon, label, color = tool_display.get(
            tool_name, ("🔧", tool_name, ACCENT)
        )

        # Show key args without cluttering
        arg_summary = ""
        if "url" in args:
            arg_summary = f" → {args['url'][:60]}"
        elif "param" in args:
            arg_summary = f" → param={args['param']}"
        elif "context" in args:
            arg_summary = f" → context={args['context']}"

        self.console.print(
            f"  {icon} [{color} bold]{label}[/]{arg_summary}",
        )

    def _on_token(self, token: str) -> None:
        """Disabled — streaming conflicts with Rich's status spinner."""
        pass

    # ──────────────────────────────────────────────────────────────
    # CONFIRMATION GATE
    # ──────────────────────────────────────────────────────────────

    def _handle_confirmation_gate(self, agent_response: str) -> str:
        """
        If the agent asks for exploitation approval, intercept and
        prompt the user. Only approve on explicit "yes".

        Returns the (possibly modified) response to display.
        """
        if not _is_exploitation_question(agent_response):
            return agent_response

        # Show the agent's question
        self.console.print()
        self.console.print(Panel(
            Markdown(agent_response),
            title="[bright_yellow bold]⚠️  CONFIRMATION GATE[/]",
            border_style="bright_yellow",
            padding=(1, 2),
        ))

        # Get explicit user approval
        self.console.print()
        self.console.print(
            f"[{NEON_YELLOW} bold]The agent wants to test payloads against your target.[/]"
        )
        self.console.print(
            f"[{DIM}]Type 'yes' to approve, anything else to deny.[/]"
        )

        try:
            response = input(f"\n  Approve exploitation? [yes/no]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            response = "no"

        if response in ("yes", "y"):
            exploit.approve_exploitation()
            self.brain.approve_exploitation()
            self.console.print(f"\n  [{NEON_GREEN} bold]✓ Exploitation APPROVED — launching payload testing...[/]")
            self.console.print()

            # Send approval back to the agent so it can proceed (show spinner — may take a while)
            with self.console.status(
                f"[{ACCENT}] Sentry executing payloads...",
                spinner="dots",
                spinner_style=ACCENT,
            ):
                result = self.brain.handle_message("Yes, proceed with exploitation testing.")
            return result
        else:
            exploit.revoke_exploitation()
            self.brain.revoke_exploitation()
            self.console.print(f"\n  [{NEON_RED} bold]✗ Exploitation DENIED[/]")
            return "Understood. Exploitation testing has been denied. I'll report my reconnaissance findings without active testing."

    # ──────────────────────────────────────────────────────────────
    # DISPLAY HELPERS
    # ──────────────────────────────────────────────────────────────

    def _show_banner(self) -> None:
        """Display the startup banner."""
        self.console.print(BANNER)
        self.console.print(Rule(style="bright_red"))
        if self.target_url:
            self.console.print(
                f"  [{NEON_CYAN}]Target:[/] [{NEON_GREEN} bold]{self.target_url}[/]"
            )
        else:
            self.console.print(
                f"  [{NEON_CYAN}]Target:[/] [{NEON_YELLOW} bold][NOT SET][/] [{DIM}]— type [bold]/target <url>[/bold] to set target[/]"
            )
        self.console.print(
            f"  [{NEON_CYAN}]Model:[/]  [{DIM}]{self.brain.model}[/]"
        )
        from xssentry.llm_brain import TOOL_REGISTRY
        tools_list = ", ".join(TOOL_REGISTRY.keys()) or "none loaded"
        self.console.print(
            f"  [{NEON_CYAN}]Tools:[/]  [{DIM}]{tools_list}[/]"
        )
        self.console.print(Rule(style="bright_red"))
        self.console.print()
        self.console.print(
            f"  [{DIM}]Type [bold]/[/bold] for commands or start chatting with Sentry AI.[/]"
        )
        self.console.print()

    def _display_agent_response(self, response: str) -> None:
        """Display the agent's response in a styled panel."""
        if not response.strip():
            return

        self.console.print()
        self.console.print(Panel(
            Markdown(response),
            title=f"[{NEON_GREEN} bold]🤖 Sentry[/]",
            border_style=NEON_GREEN,
            padding=(1, 2),
        ))

    def _display_findings_summary(self) -> None:
        """Display a summary table of current findings."""
        findings = self.brain.get_findings()

        if not findings:
            self.console.print(f"\n  [{DIM}]No confirmed findings yet.[/]\n")
            return

        table = Table(
            title="XSS Findings",
            box=box.ROUNDED,
            border_style=NEON_RED,
            title_style=f"{NEON_RED} bold",
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("URL", style=NEON_CYAN, max_width=40)
        table.add_column("Param", style=NEON_YELLOW)
        table.add_column("Context", style=NEON_GREEN)
        table.add_column("Severity", style=NEON_RED)

        for i, f in enumerate(findings, 1):
            severity = f.get("severity_assessment", {}).get("severity", "?")
            table.add_row(
                str(i),
                f.get("url", "?")[:40],
                f.get("param", "?"),
                f.get("context", "?"),
                severity,
            )

        self.console.print()
        self.console.print(table)
        self.console.print()

    def _show_help(self) -> None:
        """Display help information."""
        help_text = """
[bright_cyan bold]XSSentry Slash Commands:[/]

  [bright_green]/target <url>[/]   Set or change target URL (e.g. /target http://testphp.vulnweb.com)
  [bright_green]/spider[/]         Run Hellhound Spider engine to crawl and discover endpoints & parameters
  [bright_green]/recon[/]          Run HTTP reconnaissance to fingerprint security posture and base inputs
  [bright_green]/submit[/]         Test discovered forms for Stored XSS (href injection, comment forms)
  [bright_green]/skills[/]         Analyze target profile and display applicable XSS techniques
  [bright_green]/status[/]         Show current findings and discovered attack surface summary
  [bright_green]/reset[/]          Reset agent context and findings (keep conversation history)
  [bright_green]/help[/]           Show this command menu
  [bright_green]/quit[/]           Exit XSSentry console

  [bright_green]start / <enter>[/] Run full autonomous pipeline (recon → spider → skills → payload selection)
  [bright_green]continue / c[/]   Resume testing remaining vectors

  [dim]Any standard text message will be answered directly by Sentry AI.[/]
"""
        self.console.print(help_text)

    def _show_slash_suggestions(self) -> None:
        """Display a styled slash-command suggestion menu when user types '/'."""
        table = Table(
            title="⚡ Available Commands",
            box=box.ROUNDED,
            border_style=NEON_CYAN,
            title_style=f"{NEON_CYAN} bold",
            padding=(0, 2),
            show_lines=True,
        )
        table.add_column("Command", style=f"{NEON_GREEN} bold", min_width=18)
        table.add_column("Description", style="white")
        table.add_column("Category", style=DIM, justify="center")

        commands = [
            ("/target <url>", "Set or change the target URL",                    "🎯 Target"),
            ("/recon",        "HTTP reconnaissance — fingerprint headers & inputs", "🔍 Scanning"),
            ("/spider",       "Hellhound Spider — crawl all endpoints & forms",    "🕷️ Scanning"),
            ("/submit",       "Test forms for Stored XSS (href injection)",        "📝 Exploit"),
            ("/skills",       "Analyse attack surface & recommend XSS techniques", "🧠 Analysis"),
            ("/status",       "Show confirmed findings & discovered vectors",      "📊 Results"),
            ("/reset",        "Clear agent context & findings",                    "⚙️ Session"),
            ("/help",         "Show full help menu",                               "📋 General"),
            ("/quit",         "Exit XSSentry console",                             "📋 General"),
        ]

        for cmd, desc, cat in commands:
            table.add_row(cmd, desc, cat)

        self.console.print()
        self.console.print(table)
        self.console.print()
        self.console.print(
            f"  [{DIM}]Type a command above, or just type a message to chat with Sentry AI.[/]"
        )
        self.console.print()

    # ──────────────────────────────────────────────────────────────
    # MAIN LOOP
    # ──────────────────────────────────────────────────────────────

    def run(self) -> None:
        """Main interactive chat loop."""
        self._show_banner()

        # Auto-start message only if target_url was already provided
        initial_msg = None
        if self.target_url:
            initial_msg = (
                f"I've connected to XSSentry targeting {self.target_url}. "
                "Begin autonomous XSS reconnaissance on this target. "
                "Start by running recon to discover input fields, then analyze "
                "the attack surface."
            )

        while True:
            try:
                # Get user input
                self.console.print()
                try:
                    user_input = input(f"  \033[38;5;82m❯\033[0m ").strip()
                except (EOFError, KeyboardInterrupt):
                    self.console.print(f"\n  [{DIM}]Goodbye.[/]")
                    break

                cmd_lower = user_input.lower()

                # ── 0. Slash Suggestion Menu (user typed just "/") ──
                if cmd_lower == "/":
                    self._show_slash_suggestions()
                    continue

                # ── 1. Slash Commands (/target, /spider, /recon, /skills, /status, /reset, /help, /quit) ──
                if cmd_lower.startswith("/target") or (cmd_lower.startswith("target ") and not self.target_url):
                    parts = user_input.split(maxsplit=1)
                    if len(parts) < 2 or not parts[1].strip():
                        self.console.print(
                            f"  [{NEON_YELLOW} bold]Usage:[/] /target <url>  (e.g. /target http://testphp.vulnweb.com)"
                        )
                        continue
                    new_target = parts[1].strip()
                    try:
                        from xssentry.cli import _validate_url
                        validated_url = _validate_url(new_target)
                    except Exception as e:
                        self.console.print(f"  [{NEON_RED} bold]❌ Invalid URL:[/] {e}")
                        continue

                    self.set_target(validated_url)
                    exploit.revoke_exploitation()
                    self.console.print(f"\n  [{NEON_GREEN} bold]✓ Target set to:[/] [{NEON_CYAN} bold]{validated_url}[/]")
                    self.console.print(f"  [{DIM}]Type /spider to crawl, /recon for posture, or press Enter for full scan.[/]\n")
                    initial_msg = (
                        f"Target set to {self.target_url}. "
                        "Begin autonomous XSS reconnaissance on this target."
                    )
                    continue

                elif cmd_lower in ("/spider", "spider", "crawl", "/crawl"):
                    if not self.target_url:
                        self.console.print(
                            f"  [{NEON_YELLOW} bold]⚠️ No target set.[/] Set target first using: [{NEON_GREEN} bold]/target <url>[/]"
                        )
                        continue
                    self.console.print(f"  [{ACCENT}]🕷️ Executing Hellhound Spider crawling engine...[/]")
                    user_input = (
                        f"Target: {self.target_url}\n"
                        "Run the Hellhound Spider ('run_spider') to thoroughly crawl and map all endpoints, forms, and input parameters."
                    )

                elif cmd_lower in ("/recon", "recon"):
                    if not self.target_url:
                        self.console.print(
                            f"  [{NEON_YELLOW} bold]⚠️ No target set.[/] Set target first using: [{NEON_GREEN} bold]/target <url>[/]"
                        )
                        continue
                    self.console.print(f"  [{ACCENT}]🔍 Executing HTTP reconnaissance...[/]")
                    user_input = (
                        f"Target: {self.target_url}\n"
                        "Run HTTP reconnaissance ('run_recon') on the target to fingerprint headers and extract input fields."
                    )

                elif cmd_lower in ("/skills", "skills", "analyze", "/analyze"):
                    if not self.target_url:
                        self.console.print(
                            f"  [{NEON_YELLOW} bold]⚠️ No target set.[/] Set target first using: [{NEON_GREEN} bold]/target <url>[/]"
                        )
                        continue
                    self.console.print(f"  [{ACCENT}]🧠 Analyzing target attack surface skills...[/]")
                    user_input = (
                        f"Target: {self.target_url}\n"
                        "Call 'analyse_target_skills' to evaluate applicable XSS techniques and recommend the best workflow."
                    )

                elif cmd_lower in ("/submit", "submit", "/stored", "stored"):
                    if not self.target_url:
                        self.console.print(
                            f"  [{NEON_YELLOW} bold]⚠️ No target set.[/] Set target first using: [{NEON_GREEN} bold]/target <url>[/]"
                        )
                        continue
                    self.console.print(f"  [{ACCENT}]📝 Triggering Stored XSS form submission testing...[/]")
                    user_input = (
                        f"Target: {self.target_url}\n"
                        "Find all forms on the target (especially comment/feedback/profile forms). "
                        "Look for fields like 'website', 'url', 'homepage' that may render into <a href=\"...\">. "
                        "Use submit_form to test javascript:alert(1) in those fields and verify stored reflection."
                    )

                elif cmd_lower in ("/status", "status"):
                    self._display_findings_summary()
                    continue

                elif cmd_lower in ("/reset", "reset"):
                    self.brain.reset_context()
                    exploit.revoke_exploitation()
                    self.console.print(f"  [{NEON_YELLOW}]Context reset.[/]")
                    continue

                elif cmd_lower in ("/help", "help", "?", "/?"):
                    self._show_help()
                    continue

                elif cmd_lower in ("/quit", "/exit", "quit", "exit", "q"):
                    self.console.print(f"\n  [{DIM}]Goodbye.[/]")
                    break

                elif user_input.startswith("/"):
                    # Unknown slash command — do NOT fall through to autonomous scan
                    self.console.print(
                        f"  [{NEON_YELLOW} bold]⚠️ Unknown command:[/] [{NEON_RED}]{user_input}[/]"
                    )
                    self.console.print(
                        f"  [{DIM}]Type [bold]/help[/bold] to see all available commands.[/]"
                    )
                    continue

                # ── 2. Standard Start/Continue Flow ──
                is_start_cmd = (
                    not user_input
                    or cmd_lower in ("start", "begin", "run", "scan", "hunt", "go", "auto")
                )

                if is_start_cmd:
                    if not self.target_url:
                        self.console.print(
                            f"  [{NEON_YELLOW} bold]⚠️ No target set.[/] Please specify a target first using: [{NEON_GREEN} bold]/target <url>[/]"
                        )
                        self.console.print(f"  [{DIM}]Example: /target http://testphp.vulnweb.com[/]")
                        continue

                    if not user_input and not initial_msg:
                        continue
                    initial_msg = None
                    self.console.print(f"  [{ACCENT}]⚡ Starting autonomous recon & Hellhound spider on target...[/]")
                    user_input = (
                        f"Target: {self.target_url}\n"
                        "Execute full autonomous hunting:\n"
                        "1. Run curl reconnaissance ('run_recon') on the target to fingerprint and check base endpoints.\n"
                        "2. Run the Hellhound Spider ('run_spider') to thoroughly discover all endpoints, forms, and input parameters.\n"
                        "3. Consolidate all discovered attack vectors and endpoints.\n"
                        "4. Select context-aware XSS payloads for testing and immediately ask the confirmation gate ('Shall I proceed with exploitation testing?') so we can begin exploitation."
                    )

                elif cmd_lower in ("continue", "proceed", "keep testing", "more", "c"):
                    if not self.target_url:
                        self.console.print(f"  [{NEON_YELLOW} bold]⚠️ No target set.[/] Use [bold]/target <url>[/] first.")
                        continue
                    self.console.print(f"  [{ACCENT}]⚡ Resuming testing on remaining endpoints and parameters...[/]")
                    user_input = (
                        "Resume testing: evaluate the remaining parameters and endpoints that have not yet been tested. "
                        "Execute test_payload with context-tailored payloads and report the findings."
                    )



                # Send to agent
                self.console.print()
                self.console.print(Rule(characters="─", style="dim"))

                # Show thinking indicator while agent works
                with self.console.status(
                    f"[{ACCENT}] Sentry thinking...",
                    spinner="dots",
                    spinner_style=ACCENT,
                ):
                    response = self.brain.handle_message(user_input)

                # Handle confirmation gate
                response = self._handle_confirmation_gate(response)

                # Display the final response in a clean panel
                self._display_agent_response(response)

            except KeyboardInterrupt:
                self.console.print(f"\n  [{DIM}]Interrupted. Type 'quit' to exit.[/]")
                continue
            except Exception as e:
                logger.error("Chat loop error: %s", e, exc_info=True)
                self.console.print(f"\n  [{NEON_RED}]Error: {e}[/]")
                continue

        # Cleanup
        exploit.revoke_exploitation()
