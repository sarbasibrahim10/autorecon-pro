from __future__ import annotations
import asyncio
import random
import time
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
import httpx
from core.models import Finding, Endpoint
from scanners.base_scanner import BaseScanner
import re

DB_ERROR_PATTERNS = [
    (re.compile(r"SQL syntax.*?MySQL", re.I), "MySQL"),
    (re.compile(r"Warning.*?mysql_", re.I), "MySQL"),
    (re.compile(r"MySQLSyntaxErrorException", re.I), "MySQL"),
    (re.compile(r"valid MySQL result", re.I), "MySQL"),
    (re.compile(r"PostgreSQL.*?ERROR", re.I | re.S), "PostgreSQL"),
    (re.compile(r"Warning.*?pg_", re.I), "PostgreSQL"),
    (re.compile(r"PG::SyntaxError", re.I), "PostgreSQL"),
    (re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I), "MSSQL"),
    (re.compile(r"OLE DB.*?SQL Server", re.I), "MSSQL"),
    (re.compile(r"Unclosed quotation mark.*?string", re.I), "MSSQL"),
    (re.compile(r"ORA-\d{5}", re.I), "Oracle"),
    (re.compile(r"Oracle.*?Error", re.I), "Oracle"),
    (re.compile(r"SQLite.*?error", re.I), "SQLite"),
    (re.compile(r"syntax error at or near", re.I), "PostgreSQL"),
    (re.compile(r"Incorrect syntax near", re.I), "MSSQL"),
    (re.compile(r"unterminated quoted string", re.I), "PostgreSQL"),
    (re.compile(r"SQLSTATE\[", re.I), "Generic"),
    (re.compile(r"Syntax error.*?query", re.I), "Generic"),
]

ERROR_PAYLOADS = ["'", "''", '"', "1'--", '1"--', "1 AND '1'='2"]
BOOL_TRUE = "1 AND 1=1--"
BOOL_FALSE = "1 AND 1=2--"
TIME_PAYLOADS = [
    ("1; SELECT SLEEP(5)--", 5),
    ("1' AND SLEEP(5)--", 5),
    ("1; SELECT pg_sleep(5)--", 5),
    ("1; WAITFOR DELAY '0:0:5'--", 5),
]

EXCLUDED_PATH_PATTERNS = [
    "/_next/image", "/_next/static", "/__next",
    "/cdn-cgi/", "/static/", "/assets/", "/images/",
    "/img/", "/favicon", "/robots.txt", "/sitemap",
    "/.well-known/", "/webpack",
]
EXCLUDED_PARAMS_FOR_PATHS = {"/_next/image": ["url", "w", "q"]}
GLOBALLY_EXCLUDED_PARAMS = [
    "width", "height", "size", "format", "quality",
    "w", "h", "callback", "jsonp", "lang", "locale",
    "v", "ver", "version", "_", "t", "ts",
]
NON_DB_CONTENT_TYPES = [
    "image/", "video/", "audio/", "font/",
    "application/octet-stream", "text/css",
    "text/javascript", "application/javascript",
]


class SQLiScanner(BaseScanner):
    name = "sqli"
    finding_type = "SQL Injection"
    severity = "Critical"

    def is_applicable(self, target) -> bool:
        if not isinstance(target, Endpoint) or not target.parameters:
            return False
        return not self._is_excluded_endpoint(target)

    def _is_excluded_endpoint(self, ep: Endpoint) -> bool:
        path = urlparse(ep.url).path.lower()
        return any(p in path for p in EXCLUDED_PATH_PATTERNS)

    def _is_excluded_param(self, ep: Endpoint, param: str) -> bool:
        if param.lower() in GLOBALLY_EXCLUDED_PARAMS:
            return True
        path = urlparse(ep.url).path.lower()
        for path_pattern, excluded in EXCLUDED_PARAMS_FOR_PATHS.items():
            if path_pattern in path and param.lower() in excluded:
                return True
        return False

    def _is_non_db_response(self, r: httpx.Response) -> bool:
        ct = r.headers.get("content-type", "").lower()
        return any(ct.startswith(t) for t in NON_DB_CONTENT_TYPES)

    async def scan(self, target: Endpoint) -> list[Finding]:
        findings = []
        for param in target.parameters:
            if self._is_excluded_param(target, param):
                continue
            await asyncio.sleep(random.uniform(0.3, 0.8))
            f = await self._error_based(target, param)
            if f:
                findings.append(f)
                continue
            await asyncio.sleep(random.uniform(0.2, 0.5))
            f = await self._boolean_based(target, param)
            if f:
                findings.append(f)
                continue
            await asyncio.sleep(random.uniform(0.2, 0.5))
            f = await self._time_based(target, param)
            if f:
                findings.append(f)
        return findings

    async def _error_based(self, ep: Endpoint, param: str) -> Finding | None:
        for payload in ERROR_PAYLOADS:
            url = self._inject(ep.url, param, payload)
            r = await self._safe_get(url, timeout=12)
            if r is None:
                continue
            if self._is_non_db_response(r):
                return None
            for pattern, db_type in DB_ERROR_PATTERNS:
                if pattern.search(r.text):
                    return self.make_finding(
                        url=url, parameter=param, payload=payload,
                        evidence=f"DB error ({db_type}): " + r.text[:300],
                        description=f"Error-based SQLi in '{param}'. DB: {db_type}. Payload: {payload}",
                        remediation="Use parameterized queries. Never concatenate user input into SQL.",
                    )
        return None

    async def _boolean_based(self, ep: Endpoint, param: str) -> Finding | None:
        base_r = await self._safe_get(ep.url, timeout=10)
        if base_r is None or self._is_non_db_response(base_r):
            return None
        base_len = len(base_r.text)
        true_r = await self._safe_get(self._inject(ep.url, param, BOOL_TRUE), timeout=10)
        false_r = await self._safe_get(self._inject(ep.url, param, BOOL_FALSE), timeout=10)
        if true_r is None or false_r is None:
            return None
        if abs(len(true_r.text) - base_len) < 50 and abs(len(false_r.text) - base_len) > 100:
            self.severity = "High"
            return self.make_finding(
                url=self._inject(ep.url, param, BOOL_TRUE),
                parameter=param, payload=BOOL_TRUE,
                evidence=f"True: {len(true_r.text)}b, False: {len(false_r.text)}b (diff: {abs(len(true_r.text)-len(false_r.text))})",
                description=f"Boolean-based blind SQLi in '{param}'.",
                remediation="Use parameterized queries.",
            )
        return None

    async def _time_based(self, ep: Endpoint, param: str) -> Finding | None:
        """Triple-verified: ALL 3 attempts must delay to confirm."""
        base_times = []
        for _ in range(3):
            start = time.monotonic()
            r = await self._safe_get(ep.url, timeout=15)
            base_times.append(time.monotonic() - start)
            if r is None or self._is_non_db_response(r):
                return None
            await asyncio.sleep(random.uniform(0.2, 0.5))
        base_time = sum(base_times) / 3

        for payload, sleep_secs in TIME_PAYLOADS:
            url = self._inject(ep.url, param, payload)
            delays = []
            for attempt in range(3):
                start = time.monotonic()
                await self._safe_get(url, timeout=sleep_secs + 8)
                elapsed = time.monotonic() - start
                delays.append(elapsed)
                if elapsed < (base_time + sleep_secs - 1.5):
                    break
                if attempt < 2:
                    await asyncio.sleep(random.uniform(0.5, 1.0))

            if len(delays) == 3 and all(d >= (base_time + sleep_secs - 1.5) for d in delays):
                avg = sum(delays) / 3
                self.severity = "High"
                return self.make_finding(
                    url=url, parameter=param, payload=payload,
                    evidence=f"Consistent delay ~{avg:.1f}s (baseline: {base_time:.1f}s, verified 3/3)",
                    description=f"Time-based blind SQLi in '{param}' (verified 3x).",
                    remediation="Use parameterized queries.",
                )
        return None

    def _inject(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
