from __future__ import annotations
import re
import httpx
from core.models import Finding, Endpoint
from scanners.base_scanner import BaseScanner

REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "Medium",
        "desc": "HSTS header missing — site is vulnerable to protocol downgrade attacks.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "Content-Security-Policy": {
        "severity": "Medium",
        "desc": "Content Security Policy missing — increases XSS risk.",
        "remediation": "Implement a CSP header to restrict allowed content sources."
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "desc": "X-Content-Type-Options: nosniff missing — MIME sniffing attacks possible.",
        "remediation": "Add: X-Content-Type-Options: nosniff"
    },
    "X-Frame-Options": {
        "severity": "Low",
        "desc": "X-Frame-Options missing — clickjacking attacks possible.",
        "remediation": "Add: X-Frame-Options: DENY or SAMEORIGIN"
    },
    "Referrer-Policy": {
        "severity": "Info",
        "desc": "Referrer-Policy missing — URLs may leak to external sites.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "severity": "Info",
        "desc": "Permissions-Policy missing — browser features not restricted.",
        "remediation": "Add Permissions-Policy to restrict access to camera, mic, geolocation, etc."
    },
}

VERSION_DISCLOSURE = [
    (re.compile(r"Server:\s*(Apache/[\d\.]+)", re.I), "Server version disclosure"),
    (re.compile(r"Server:\s*(nginx/[\d\.]+)", re.I), "Server version disclosure"),
    (re.compile(r"X-Powered-By:\s*(PHP/[\d\.]+)", re.I), "PHP version disclosure"),
    (re.compile(r"X-Powered-By:\s*(ASP\.NET)", re.I), "ASP.NET version disclosure"),
    (re.compile(r"X-AspNet-Version:\s*([\d\.]+)", re.I), "ASP.NET version disclosure"),
    (re.compile(r"X-AspNetMvc-Version:\s*([\d\.]+)", re.I), "ASP.NET MVC version disclosure"),
]


class HeaderScanner(BaseScanner):
    name = "headers"
    finding_type = "Security Header Missing"
    severity = "Low"

    def is_applicable(self, target) -> bool:
        return isinstance(target, Endpoint)

    async def scan(self, target: Endpoint) -> list[Finding]:
        findings = []
        try:
            r = await self.session.get(target.url, timeout=10)
            headers_str = "\r\n".join(f"{k}: {v}" for k, v in r.headers.items())
            headers_lower = {k.lower(): v for k, v in r.headers.items()}

            # Check required headers
            for header_name, info in REQUIRED_HEADERS.items():
                if header_name.lower() not in headers_lower:
                    self.finding_type = "Security Header Missing"
                    self.severity = info["severity"]
                    findings.append(self.make_finding(
                        url=target.url,
                        evidence=f"Missing: {header_name}\nResponse headers: {headers_str[:500]}",
                        description=info["desc"],
                        remediation=info["remediation"],
                    ))

            # Version disclosure
            for pattern, desc in VERSION_DISCLOSURE:
                m = pattern.search(headers_str)
                if m:
                    self.finding_type = "Information Disclosure"
                    self.severity = "Low"
                    findings.append(self.make_finding(
                        url=target.url,
                        evidence=f"Header: {m.group(0)}",
                        description=f"{desc}: {m.group(1) if m.lastindex else m.group(0)}",
                        remediation="Remove or obscure server version information from HTTP headers.",
                    ))

        except Exception:
            pass

        return findings
