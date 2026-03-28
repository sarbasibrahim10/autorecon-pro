from __future__ import annotations
import asyncio
import random
import time
from abc import ABC, abstractmethod
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
import httpx
from core.models import Finding, Endpoint, Subdomain

# -----------------------------------------------------------------------
# 10 rotating User Agents — different agent on every single request
# This is the #1 way to avoid rate limits without slowing down
# -----------------------------------------------------------------------
ROTATE_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
]


class BaseScanner(ABC):
    name: str = "base"
    severity: str = "Info"
    finding_type: str = "Base"

    MAX_RETRIES: int = 3
    BASE_BACKOFF: float = 2.0
    JITTER: float = 1.0

    def __init__(self, session: httpx.AsyncClient):
        self.session = session

    @abstractmethod
    async def scan(self, target) -> list[Finding]:
        pass

    def is_applicable(self, target) -> bool:
        return True

    # -----------------------------------------------------------------------
    # _safe_get: rotating agent + smart retry
    # NO unnecessary sleep — only waits when actually rate limited or errored
    # -----------------------------------------------------------------------
    async def _safe_get(
        self,
        url: str,
        timeout: int = 12,
        headers: dict | None = None,
        follow_redirects: bool = True,
    ) -> httpx.Response | None:
        for attempt in range(self.MAX_RETRIES):
            try:
                request_headers = {
                    "User-Agent": random.choice(ROTATE_AGENTS),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "keep-alive",
                    **(headers or {}),
                }

                r = await self.session.get(
                    url,
                    timeout=timeout,
                    headers=request_headers,
                    follow_redirects=follow_redirects,
                )

                # Only sleep when rate limited — not on every request
                if r.status_code == 429:
                    wait = self._parse_retry_after(r) + random.uniform(0, self.JITTER)
                    await asyncio.sleep(wait)
                    continue

                if r.status_code in (502, 503, 504):
                    wait = (self.BASE_BACKOFF ** attempt) + random.uniform(0, self.JITTER)
                    await asyncio.sleep(wait)
                    continue

                if r.status_code == 403 and attempt == 0:
                    await asyncio.sleep(random.uniform(1.0, 2.0))
                    continue

                return r  # success — return immediately

            except (httpx.TimeoutException, httpx.ConnectError):
                if attempt < self.MAX_RETRIES - 1:
                    await asyncio.sleep((self.BASE_BACKOFF ** attempt) + random.uniform(0, self.JITTER))
                continue
            except Exception:
                return None

        return None

    async def _safe_request(
        self,
        method: str,
        url: str,
        timeout: int = 12,
        headers: dict | None = None,
        content: bytes | None = None,
        follow_redirects: bool = True,
    ) -> httpx.Response | None:
        for attempt in range(self.MAX_RETRIES):
            try:
                request_headers = {
                    "User-Agent": random.choice(ROTATE_AGENTS),
                    **(headers or {}),
                }
                r = await self.session.request(
                    method=method, url=url, timeout=timeout,
                    headers=request_headers, content=content,
                    follow_redirects=follow_redirects,
                )
                if r.status_code == 429:
                    await asyncio.sleep(self._parse_retry_after(r) + random.uniform(0, self.JITTER))
                    continue
                if r.status_code in (502, 503, 504):
                    await asyncio.sleep((self.BASE_BACKOFF ** attempt) + random.uniform(0, self.JITTER))
                    continue
                return r
            except (httpx.TimeoutException, httpx.ConnectError):
                if attempt < self.MAX_RETRIES - 1:
                    await asyncio.sleep((self.BASE_BACKOFF ** attempt) + random.uniform(0, self.JITTER))
                continue
            except Exception:
                return None
        return None

    def _parse_retry_after(self, response: httpx.Response) -> float:
        header = response.headers.get("Retry-After", "")
        if header:
            try:
                return float(header)
            except ValueError:
                pass
            return 30.0
        return 10.0 if response.status_code == 429 else 5.0

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
