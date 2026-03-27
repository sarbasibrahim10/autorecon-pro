from __future__ import annotations
import re
import httpx
from core.models import Endpoint

# Patterns to extract API endpoints from JS
ENDPOINT_PATTERNS = [
    re.compile(r'''["'`](/api/[a-zA-Z0-9/_\-\.]+)["'`]'''),
    re.compile(r'''["'`](/v\d+/[a-zA-Z0-9/_\-\.]+)["'`]'''),
    re.compile(r'''["'`](https?://[a-zA-Z0-9\-\.]+/[a-zA-Z0-9/_\-\.\?=&]+)["'`]'''),
    re.compile(r'''fetch\s*\(\s*["'`]([^"'`]+)["'`]'''),
    re.compile(r'''axios\.[a-z]+\s*\(\s*["'`]([^"'`]+)["'`]'''),
    re.compile(r'''url\s*:\s*["'`]([^"'`]+)["'`]'''),
    re.compile(r'''endpoint\s*:\s*["'`]([^"'`]+)["'`]'''),
]

# DOM XSS sinks
DOM_XSS_SINKS = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "eval(", "setTimeout(", "setInterval(", "Function(", "execScript(",
]

DOM_XSS_SOURCES = [
    "location.hash", "location.search", "location.href",
    "document.URL", "document.referrer", "window.name",
]


class JsAnalyzer:
    def __init__(self, session: httpx.AsyncClient):
        self.session = session

    async def analyze(self, js_url: str) -> list[Endpoint]:
        endpoints = []
        try:
            r = await self.session.get(js_url, timeout=15)
            if r.status_code != 200:
                return []
            content = r.text[:500000]

            found_urls = set()
            for pattern in ENDPOINT_PATTERNS:
                for m in pattern.finditer(content):
                    path = m.group(1)
                    if path and len(path) > 3 and not path.startswith("//"):
                        found_urls.add(path)

            from urllib.parse import urlparse
            base = f"{urlparse(js_url).scheme}://{urlparse(js_url).netloc}"
            for path in found_urls:
                if path.startswith("http"):
                    full_url = path
                else:
                    full_url = base + path
                endpoints.append(Endpoint(url=full_url, source="js_analysis"))

        except Exception:
            pass
        return endpoints
