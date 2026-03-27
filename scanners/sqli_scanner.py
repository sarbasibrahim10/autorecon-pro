from __future__ import annotations
import asyncio
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


class SQLiScanner(BaseScanner):
    name = "sqli"
    finding_type = "SQL Injection"
    severity = "Critical"

    def is_applicable(self, target) -> bool:
        return isinstance(target, Endpoint) and bool(target.parameters)

    async def scan(self, target: Endpoint) -> list[Finding]:
        findings = []
        for param in target.parameters:
            # Error-based
            f = await self._error_based(target, param)
            if f:
                findings.append(f)
                continue
            # Boolean-based
            f = await self._boolean_based(target, param)
            if f:
                findings.append(f)
                continue
            # Time-based
            f = await self._time_based(target, param)
            if f:
                findings.append(f)
        return findings

    async def _error_based(self, ep: Endpoint, param: str) -> Finding | None:
        for payload in ERROR_PAYLOADS:
            url = self._inject(ep.url, param, payload)
            try:
                r = await self.session.get(url, timeout=12, follow_redirects=True)
                for pattern, db_type in DB_ERROR_PATTERNS:
                    if pattern.search(r.text):
                        return self.make_finding(
                            url=url, parameter=param, payload=payload,
                            evidence=f"DB error detected ({db_type}): " + r.text[:300],
                            description=f"Error-based SQL Injection in '{param}'. "
                                        f"Database type: {db_type}. Payload: {payload}",
                            remediation="Use parameterized queries / prepared statements. "
                                        "Never concatenate user input into SQL queries.",
                        )
            except Exception:
                continue
        return None

    async def _boolean_based(self, ep: Endpoint, param: str) -> Finding | None:
        try:
            # Baseline
            base_r = await self.session.get(ep.url, timeout=10)
            base_len = len(base_r.text)

            true_url = self._inject(ep.url, param, BOOL_TRUE)
            false_url = self._inject(ep.url, param, BOOL_FALSE)

            true_r = await self.session.get(true_url, timeout=10)
            false_r = await self.session.get(false_url, timeout=10)

            true_len = len(true_r.text)
            false_len = len(false_r.text)

            # True should match baseline, false should differ
            if abs(true_len - base_len) < 50 and abs(false_len - base_len) > 100:
                self.severity = "High"
                return self.make_finding(
                    url=true_url, parameter=param, payload=BOOL_TRUE,
                    evidence=f"True condition: {true_len} bytes, False condition: {false_len} bytes (diff: {abs(true_len-false_len)})",
                    description=f"Boolean-based blind SQL injection in '{param}'.",
                    remediation="Use parameterized queries / prepared statements.",
                )
        except Exception:
            pass
        return None

    async def _time_based(self, ep: Endpoint, param: str) -> Finding | None:
        try:
            base_start = time.monotonic()
            await self.session.get(ep.url, timeout=10)
            base_time = time.monotonic() - base_start

            for payload, sleep_secs in TIME_PAYLOADS:
                url = self._inject(ep.url, param, payload)
                try:
                    start = time.monotonic()
                    await self.session.get(url, timeout=sleep_secs + 6)
                    elapsed = time.monotonic() - start
                    if elapsed >= (base_time + sleep_secs - 1):
                        self.severity = "High"
                        return self.make_finding(
                            url=url, parameter=param, payload=payload,
                            evidence=f"Response delayed by {elapsed:.1f}s (baseline: {base_time:.1f}s)",
                            description=f"Time-based blind SQL injection in '{param}'.",
                            remediation="Use parameterized queries / prepared statements.",
                        )
                except Exception:
                    continue
        except Exception:
            pass
        return None

    def _inject(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
