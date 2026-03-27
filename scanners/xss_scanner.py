from __future__ import annotations
import asyncio
import random
import string
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
import httpx
from core.models import Finding, Endpoint
from scanners.base_scanner import BaseScanner
from utils.payload_encoder import XSS_PAYLOADS

CANARY_LEN = 8
XSS_SIGNS = ["<script>", "onerror=", "onload=", "alert(1)", "svg/onload", "<img src=x"]

EXCLUDED_PATH_PATTERNS = [
    "/_next/image", "/_next/static", "/__next",
    "/cdn-cgi/", "/static/", "/assets/", "/images/",
    "/img/", "/favicon", "/robots.txt", "/sitemap",
    "/.well-known/", "/webpack",
]
EXCLUDED_PARAMS = [
    "url", "w", "q", "width", "height", "size",
    "format", "quality", "callback", "jsonp",
    "lang", "locale", "v", "ver", "version", "_", "t", "ts",
]
HTML_CONTENT_TYPES = ["text/html", "application/xhtml"]
NON_HTML_CONTENT_TYPES = [
    "image/", "video/", "audio/", "application/json",
    "application/xml", "font/", "application/octet-stream",
    "text/css", "text/javascript", "application/javascript",
]


class XSSScanner(BaseScanner):
    name = "xss"
    finding_type = "Cross-Site Scripting (XSS)"
    severity = "High"

    def is_applicable(self, target) -> bool:
        if not isinstance(target, Endpoint):
            return False
        if not (target.parameters or target.method == "POST"):
            return False
        return not self._is_excluded_endpoint(target)

    def _is_excluded_endpoint(self, ep: Endpoint) -> bool:
        path = urlparse(ep.url).path.lower()
        return any(p in path for p in EXCLUDED_PATH_PATTERNS)

    def _is_excluded_param(self, param: str) -> bool:
        return param.lower() in EXCLUDED_PARAMS

    def _is_html_response(self, r: httpx.Response) -> bool:
        ct = r.headers.get("content-type", "").lower()
        if any(ct.startswith(t) for t in HTML_CONTENT_TYPES):
            return True
        if any(ct.startswith(t) for t in NON_HTML_CONTENT_TYPES):
            return False
        return True  # unknown — allow

    async def scan(self, target: Endpoint) -> list[Finding]:
        findings = []

        # Check baseline is HTML first
        baseline = await self._safe_get(target.url, timeout=10)
        if baseline is None or not self._is_html_response(baseline):
            return findings

        for param in (target.parameters or []):
            if self._is_excluded_param(param):
                continue

            # Small delay between params
            await asyncio.sleep(random.uniform(0.2, 0.6))

            canary = "xss" + "".join(random.choices(string.ascii_lowercase, k=CANARY_LEN))
            test_url = self._inject(target.url, param, canary)

            r = await self._safe_get(test_url, timeout=10)
            if r is None or not self._is_html_response(r):
                continue
            if canary not in r.text:
                continue  # not reflected

            for payload in XSS_PAYLOADS:
                await asyncio.sleep(random.uniform(0.1, 0.3))
                attack_url = self._inject(target.url, param, payload)
                r2 = await self._safe_get(attack_url, timeout=10)
                if r2 is None or not self._is_html_response(r2):
                    continue
                if any(sign in r2.text for sign in XSS_SIGNS):
                    snippet = self._extract_snippet(r2.text, payload)
                    f = self.make_finding(
                        url=attack_url, parameter=param, payload=payload,
                        evidence=snippet,
                        description=f"Reflected XSS in '{param}'. Payload reflected unencoded.",
                        remediation="Encode all user input before HTML rendering. "
                                    "Implement a Content Security Policy.",
                    )
                    f.poc_curl = self.generate_poc_curl(attack_url)
                    findings.append(f)
                    break

        return findings

    def _inject(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

    def _extract_snippet(self, body: str, payload: str) -> str:
        idx = body.find(payload)
        if idx == -1:
            return body[:200]
        return "..." + body[max(0, idx-100):min(len(body), idx+len(payload)+100)] + "..."
