"""
xssentry/cli.py

CLI entry point: `xssentry --url <TARGET_URL>`

Parses arguments, validates the target, and launches the interactive
chat console with the AI agent brain.
"""

import argparse
import logging
import os
import sys
from urllib.parse import urlparse

from xssentry import __version__, __codename__


def _validate_url(url: str) -> str:
    """Validate and normalize the target URL."""
    if not url:
        raise argparse.ArgumentTypeError("Target URL is required")

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    if not parsed.hostname:
        raise argparse.ArgumentTypeError(f"Invalid URL: {url}")

    return url


def _setup_logging(verbose: bool) -> None:
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # Suppress noisy third-party loggers
    logging.getLogger("urllib3").setLevel(logging.ERROR)
    logging.getLogger("requests").setLevel(logging.ERROR)
    logging.getLogger("httpx").setLevel(logging.ERROR)
    logging.getLogger("openai").setLevel(logging.WARNING)


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="xssentry",
        description=(
            f"XSSentry v{__version__} ({__codename__}) — "
            "AI-Powered Autonomous XSS Hunter [HELLHOUND-class]\n"
            "Uses NVIDIA NIM (Nemotron) as the agent brain for intelligent, "
            "context-aware XSS discovery and testing."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  xssentry\n"
            "  xssentry https://example.com/search\n"
            "  xssentry --url http://testphp.vulnweb.com/ --verbose\n"
            "  xssentry -u https://target.com --model nvidia/nemotron-3-super-120b-a12b\n"
            "\nConsole Target Command:\n"
            "  You can start without arguments and set target inside the console:\n"
            "  /target https://target.com\n"
            "\nEnvironment variables:\n"
            "  NVIDIA_API_KEY    Your NVIDIA NIM API key (required)\n"
            "  NVIDIA_MODEL      Override default model\n"
            "  NVIDIA_BASE_URL   Override NIM API endpoint\n"
        ),
    )

    # Accept URL as positional OR --url / -u flag (both work, optional)
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Optional target URL. You can also start the console directly and set target with /target <url>.",
    )
    parser.add_argument(
        "--url", "-u",
        default=None,
        help="Optional target URL (flag). You can also set target inside console with /target <url>.",
    )
    parser.add_argument(
        "--api-key", "-k",
        default=None,
        help="NVIDIA NIM API key (or set NVIDIA_API_KEY env var).",
    )
    parser.add_argument(
        "--model", "-m",
        default=None,
        help="LLM model ID (default: nvidia/nemotron-3-super-120b-a12b).",
    )
    parser.add_argument(
        "--max-iterations", "-i",
        type=int,
        default=None,
        help="Maximum agent tool-calling iterations per turn (default: 100).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug logging.",
    )
    parser.add_argument(
        "--app", "--web",
        action="store_true",
        dest="app",
        help="Launch the modern XSSentry Web Application dashboard in browser.",
    )
    parser.add_argument(
        "--desktop",
        action="store_true",
        help="Launch as a native desktop application window.",
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=8888,
        help="Port for the web/desktop application (default: 8888).",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host address for the web application dashboard (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"XSSentry v{__version__} ({__codename__})",
    )

    args = parser.parse_args()

    # Resolve URL: positional wins, then --url flag (optional: can be set in console with /target <url>)
    raw_url = args.target or args.url
    target_url = _validate_url(raw_url) if raw_url else None

    # Setup logging
    _setup_logging(args.verbose)

    # Launch Desktop Application if requested
    if args.desktop:
        from xssentry.desktop import start_desktop
        start_desktop(target_url=target_url, port=args.port)
        return

    # Launch Web Application if requested
    if args.app:
        from xssentry.app import start_server, state
        if target_url:
            state.set_target(target_url)
        start_server(host=args.host, port=args.port)
        return

    # Resolve API key: --api-key flag → env var → config file
    api_key = args.api_key or os.getenv("NVIDIA_API_KEY")
    config_model = None
    config_max_iterations = None

    # Try loading from persistent config file
    config_path = os.path.expanduser("~/.xssentry/config.json")
    if os.path.exists(config_path):
        try:
            import json
            with open(config_path, "r") as f:
                cfg = json.load(f)
            if not api_key:
                api_key = cfg.get("nvidia_api_key", "")
            config_model = cfg.get("model")
            config_max_iterations = cfg.get("max_iterations")
        except Exception:
            pass

    if not api_key:
        print(
            "\n  ❌ NVIDIA API key required.\n"
            "     Set NVIDIA_API_KEY environment variable, pass --api-key,\n"
            "     or create ~/.xssentry/config.json with:\n"
            '     {"nvidia_api_key": "nvapi-..."}\n'
            "     Get a key at: https://build.nvidia.com/\n"
        )
        sys.exit(1)

    # Model & Max Iterations resolution
    model = args.model or config_model
    max_iterations = args.max_iterations or config_max_iterations or 100

    # Import here to avoid circular imports and slow startup on --help
    # These imports also trigger tool registration via module-level register_tool() calls
    from xssentry import recon      # noqa: F401 — registers run_recon
    from xssentry import spider     # noqa: F401 — registers run_spider
    from xssentry import payloads   # noqa: F401 — registers get_payloads, generate_adaptive_payload
    from xssentry import exploit    # noqa: F401 — registers test_payload
    from xssentry import xss_skills # noqa: F401 — registers analyse_target_skills, learn_new_skill
    from xssentry import form_submit  # noqa: F401 — registers submit_form
    from xssentry.chat import ChatConsole

    # Launch the chat console
    try:
        console = ChatConsole(
            target_url=target_url,
            api_key=api_key,
            model=model,
            max_iterations=max_iterations,
        )
        console.run()
    except ValueError as e:
        print(f"\n  ❌ {e}\n")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n  Goodbye.")
        sys.exit(0)


if __name__ == "__main__":
    main()
