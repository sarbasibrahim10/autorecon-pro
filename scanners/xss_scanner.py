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

# Max params to test in parallel per endpoint
PARAM_CONCURRENCY = 4


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
        return True

    async def scan(self, target: Endpoint) -> list[Finding]:
        # Check baseline is HTML first — one request, no wasted work
        baseline = await self._safe_get(target.url, timeout=10)
        if baseline is None or not self._is_html_response(baseline):
            return []

        valid_params = [
            p for p in (target.parameters or [])
            if not self._is_excluded_param(p)
        ]
        if not valid_params:
            return []

        # ---------------------------------------------------------------
        # Parallel param scanning — test up to 4 params simultaneously
        # Each param: canary check first, then payloads only if reflected
        # ---------------------------------------------------------------
        sem = asyncio.Semaphore(PARAM_CONCURRENCY)
        findings = []

        async def scan_param(param: str) -> Finding | None:
            async with sem:
                return await self._test_param(target, param)

        results = await asyncio.gather(
            *[scan_param(p) for p in valid_params],
            return_exceptions=True
        )

        for r in results:
            if r and isinstance(r, Finding):
                findings.append(r)

        return findings

    async def _test_param(self, target: Endpoint, param: str) -> Finding | None:
        # Step 1: canary reflection check — fast, no payload yet
        canary = "xss" + "".join(random.choices(string.ascii_lowercase, k=CANARY_LEN))
        r = await self._safe_get(self._inject(target.url, param, canary), timeout=10)
        if r is None or not self._is_html_response(r):
            return None
        if canary not in r.text:
            return None  # not reflected — skip immediately

        # Step 2: try payloads — only fires if canary was reflected
        for payload in XSS_PAYLOADS:
            r2 = await self._safe_get(
                self._inject(target.url, param, payload), timeout=10
            )
            if r2 is None or not self._is_html_response(r2):
                continue
            if any(sign in r2.text for sign in XSS_SIGNS):
                f = self.make_finding(
                    url=self._inject(target.url, param, payload),
                    parameter=param, payload=payload,
                    evidence=self._extract_snippet(r2.text, payload),
                    description=f"Reflected XSS in '{param}'. Payload reflected unencoded.",
                    remediation="Encode all user input before HTML rendering. Implement CSP.",
                )
                f.poc_curl = self.generate_poc_curl(self._inject(target.url, param, payload))
                return f

        return None

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
