"""
xssentry/guard.py

Scope enforcement + safety guardrails.

Adapted from bounty-hunter's guard.py pattern:
  - ScopeGuard: ensures all tool URLs stay within the authorized target
  - RateLimiter: per-host request pacing
  - CircuitBreaker: stops hammering dead/blocked hosts
"""

import time
import logging
from typing import Any, Dict, Optional, Set
from urllib.parse import urlparse

logger = logging.getLogger("xssentry.guard")


# ═══════════════════════════════════════════════════════════════════
# SCOPE GUARD
# ═══════════════════════════════════════════════════════════════════

class ScopeGuard:
    """
    Enforces that all network requests stay within the authorized target.

    The target URL passed via --url is the ONLY authorized scope.
    All tool executors MUST call check_url() before making requests.
    """

    def __init__(self, target_url: str):
        parsed = urlparse(target_url)
        self.target_scheme = parsed.scheme or "https"
        self.target_host = parsed.hostname or ""
        self.target_port = parsed.port
        self.target_origin = f"{self.target_scheme}://{self.target_host}"
        if self.target_port and self.target_port not in (80, 443):
            self.target_origin += f":{self.target_port}"

        logger.info("ScopeGuard initialized — authorized target: %s", self.target_origin)

    def check_url(self, url: str) -> Dict[str, Any]:
        """
        Check if a URL is within the authorized target scope.

        Returns:
            {"allowed": True/False, "reason": "..."} 
        """
        if not url:
            return {"allowed": False, "reason": "Empty URL"}

        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        target_host = self.target_host.lower()

        # Exact host match or subdomain match
        if host == target_host or host.endswith(f".{target_host}"):
            return {"allowed": True, "reason": "In scope"}

        return {
            "allowed": False,
            "reason": f"URL '{url}' is outside authorized scope ({self.target_origin})",
        }

    def enforce(self, url: str) -> None:
        """Raise ValueError if URL is out of scope."""
        result = self.check_url(url)
        if not result["allowed"]:
            raise ValueError(f"SCOPE VIOLATION: {result['reason']}")


# ═══════════════════════════════════════════════════════════════════
# RATE LIMITER
# ═══════════════════════════════════════════════════════════════════

class RateLimiter:
    """Per-host rate limiter for requests."""

    def __init__(self, recon_rps: float = 10.0, test_rps: float = 2.0):
        self._last_request: Dict[str, float] = {}
        self.recon_interval = 1.0 / max(0.001, recon_rps)
        self.test_interval = 1.0 / max(0.001, test_rps)

    def wait(self, host: str, is_recon: bool = True) -> float:
        """Wait until rate limit allows the next request. Returns seconds waited."""
        interval = self.recon_interval if is_recon else self.test_interval
        now = time.monotonic()
        last = self._last_request.get(host, 0.0)
        elapsed = now - last
        wait_time = max(0.0, interval - elapsed)

        if wait_time > 0:
            time.sleep(wait_time)

        self._last_request[host] = time.monotonic()
        return wait_time


# ═══════════════════════════════════════════════════════════════════
# CIRCUIT BREAKER
# ═══════════════════════════════════════════════════════════════════

class CircuitBreaker:
    """Prevents hammering blocked, dead, or failing hosts."""

    def __init__(self, threshold: int = 5, cooldown: float = 60.0):
        self.threshold = threshold
        self.cooldown = cooldown
        self._failures: Dict[str, int] = {}
        self._tripped_at: Dict[str, float] = {}

    def record_success(self, host: str) -> None:
        self._failures[host] = 0
        self._tripped_at.pop(host, None)

    def record_failure(self, host: str) -> bool:
        """Record a failure. Returns True if breaker just tripped."""
        self._failures[host] = self._failures.get(host, 0) + 1
        if self._failures[host] >= self.threshold:
            self._tripped_at[host] = time.monotonic()
            return True
        return False

    def is_tripped(self, host: str) -> bool:
        if host not in self._tripped_at:
            return False
        elapsed = time.monotonic() - self._tripped_at[host]
        if elapsed >= self.cooldown:
            self._failures[host] = self.threshold - 1
            del self._tripped_at[host]
            return False
        return True


# ═══════════════════════════════════════════════════════════════════
# UNIFIED GUARD
# ═══════════════════════════════════════════════════════════════════

class XSSentryGuard:
    """
    Unified pre-request guard. Combines scope, rate limiting, circuit breaker.
    Every tool executor should call guard.pre_request() before HTTP requests.
    """

    def __init__(self, target_url: str):
        self.scope = ScopeGuard(target_url)
        self.limiter = RateLimiter()
        self.breaker = CircuitBreaker()

    def pre_request(self, url: str, is_recon: bool = True) -> Dict[str, Any]:
        """
        Full pre-request check: scope → circuit breaker → rate limit.

        Returns {"allowed": True} or {"allowed": False, "reason": "..."}.
        """
        # 1. Scope check
        scope_result = self.scope.check_url(url)
        if not scope_result["allowed"]:
            return scope_result

        # 2. Circuit breaker
        host = urlparse(url).hostname or "unknown"
        if self.breaker.is_tripped(host):
            return {
                "allowed": False,
                "reason": f"Circuit breaker tripped for {host} — too many consecutive failures",
            }

        # 3. Rate limit (blocking wait)
        self.limiter.wait(host, is_recon=is_recon)

        return {"allowed": True, "reason": "Cleared"}

    def record_success(self, url: str) -> None:
        host = urlparse(url).hostname or "unknown"
        self.breaker.record_success(host)

    def record_failure(self, url: str) -> bool:
        host = urlparse(url).hostname or "unknown"
        return self.breaker.record_failure(host)
