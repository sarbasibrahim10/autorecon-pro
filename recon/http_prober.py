from __future__ import annotations
import asyncio
import re
from html.parser import HTMLParser
import httpx
from core.models import Subdomain
from core.rate_limiter import RateLimiter
from utils.fingerprinter import fingerprint

TITLE_RE = re.compile(r'<title[^>]*>([^<]{1,200})</title>', re.IGNORECASE)


class HttpProber:
    def __init__(self, session: httpx.AsyncClient, rate_limiter: RateLimiter, timeout: int = 10):
        self.session = session
        self.rate_limiter = rate_limiter
        self.timeout = timeout

    async def probe(self, sub: Subdomain) -> Subdomain:
        domain = sub.domain

        for scheme in ["https", "http"]:
            url = f"{scheme}://{domain}"
            try:
                await self.rate_limiter.acquire(domain)
                r = await self.session.get(url, timeout=self.timeout)
                sub.is_live = True
                if scheme == "https":
                    sub.https_status = r.status_code
                else:
                    sub.http_status = r.status_code
                sub.final_url = str(r.url)

                body = r.text[:50000]
                # Title
                m = TITLE_RE.search(body)
                if m:
                    sub.title = m.group(1).strip()[:100]

                # Fingerprint
                sub.technologies = fingerprint(dict(r.headers), body)

                if not sub.ip_address:
                    try:
                        import socket
                        sub.ip_address = socket.gethostbyname(domain)
                    except Exception:
                        pass
                break  # prefer https, stop after first success
            except Exception:
                continue

        return sub
