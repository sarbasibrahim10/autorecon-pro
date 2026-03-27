from __future__ import annotations
import asyncio
import random
import time
from abc import ABC, abstractmethod
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
import httpx
from core.models import Finding, Endpoint, Subdomain


class BaseScanner(ABC):
    name: str = "base"
    severity: str = "Info"
    finding_type: str = "Base"

    # Rate limit settings — override in subclasses if needed
    MAX_RETRIES: int = 3
    BASE_BACKOFF: float = 2.0   # seconds (doubles each retry)
    JITTER: float = 1.0         # random jitter added to backoff

    def __init__(self, session: httpx.AsyncClient):
        self.session = session

    @abstractmethod
    async def scan(self, target) -> list[Finding]:
        pass

    def is_applicable(self, target) -> bool:
        return True

    # -----------------------------------------------------------------------
    # Core HTTP method — use this in ALL scanners instead of self.session.get
    # Handles: 429 rate limiting, 503/502 server errors, network timeouts
    # -----------------------------------------------------------------------
    async def _safe_get(
        self,
        url: str,
        timeout: int = 12,
        headers: dict | None = None,
        follow_redirects: bool = True,
    ) -> httpx.Response | None:
        """
        GET with automatic retry + exponential backoff on rate limit responses.
        Returns None if all retries are exhausted or a permanent error occurs.
        """
        for attempt in range(self.MAX_RETRIES):
            try:
                r = await self.session.get(
                    url,
                    timeout=timeout,
                    headers=headers or {},
                    follow_redirects=follow_redirects,
                )

                # 429 Too Many Requests — respect Retry-After or back off
                if r.status_code == 429:
                    retry_after = self._parse_retry_after(r)
                    wait = retry_after + random.uniform(0, self.JITTER)
                    await asyncio.sleep(wait)
                    continue  # retry

                # Transient server errors — exponential backoff
                if r.status_code in (502, 503, 504):
                    wait = (self.BASE_BACKOFF ** attempt) + random.uniform(0, self.JITTER)
                    await asyncio.sleep(wait)
                    continue  # retry

                # 403 on first attempt only — might be a WAF block
                if r.status_code == 403 and attempt == 0:
                    # Small jitter pause before retry (some WAFs are time-based)
                    await asyncio.sleep(random.uniform(1.0, 3.0))
                    continue

                return r  # success or permanent error (4xx except 429/403)

            except (httpx.TimeoutException, httpx.ConnectError):
                if attempt < self.MAX_RETRIES - 1:
                    wait = (self.BASE_BACKOFF ** attempt) + random.uniform(0, self.JITTER)
                    await asyncio.sleep(wait)
                continue

            except Exception:
                # Unknown error — don't retry
                return None

        return None  # All retries exhausted

    async def _safe_request(
        self,
        method: str,
        url: str,
        timeout: int = 12,
        headers: dict | None = None,
        content: bytes | None = None,
        follow_redirects: bool = True,
    ) -> httpx.Response | None:
        """
        Generic request with retry logic — for POST/PUT/DELETE scanners.
        """
        for attempt in range(self.MAX_RETRIES):
            try:
                r = await self.session.request(
                    method=method,
                    url=url,
                    timeout=timeout,
                    headers=headers or {},
                    content=content,
                    follow_redirects=follow_redirects,
                )

                if r.status_code == 429:
                    wait = self._parse_retry_after(r) + random.uniform(0, self.JITTER)
                    await asyncio.sleep(wait)
                    continue

                if r.status_code in (502, 503, 504):
                    wait = (self.BASE_BACKOFF ** attempt) + random.uniform(0, self.JITTER)
                    await asyncio.sleep(wait)
                    continue

                return r

            except (httpx.TimeoutException, httpx.ConnectError):
                if attempt < self.MAX_RETRIES - 1:
                    wait = (self.BASE_BACKOFF ** attempt) + random.uniform(0, self.JITTER)
                    await asyncio.sleep(wait)
                continue

            except Exception:
                return None

        return None

    def _parse_retry_after(self, response: httpx.Response) -> float:
        """
        Parse the Retry-After header. Supports both integer seconds
        and HTTP-date formats. Falls back to a safe default.
        """
        header = response.headers.get("Retry-After", "")
        if header:
            try:
                return float(header)
            except ValueError:
                pass
            # HTTP-date format — just use a safe default
            return 30.0
        # No header — default backoff based on status
        return 10.0 if response.status_code == 429 else 5.0

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------
    def generate_poc_curl(self, url: str, method: str = "GET",
                          headers: dict | None = None, body: str = "") -> str:
        h_flags = ""
        if headers:
            for k, v in headers.items():
                h_flags += f" -H '{k}: {v}'"
        if method == "POST" and body:
            return f"curl -sk -X POST{h_flags} '{url}' --data '{body}'"
        return f"curl -sk{h_flags} '{url}'"

    def make_finding(self, *, url: str, parameter: str = "", payload: str = "",
                     evidence: str = "", description: str = "", remediation: str = "",
                     source: str = "autorecon", template_id: str = "") -> Finding:
        return Finding(
            finding_type=self.finding_type,
            severity=self.severity,
            url=url,
            parameter=parameter,
            payload=payload,
            evidence=evidence[:2000],
            poc_curl=self.generate_poc_curl(url),
            description=description,
            remediation=remediation,
            source=source,
            template_id=template_id,
        )
