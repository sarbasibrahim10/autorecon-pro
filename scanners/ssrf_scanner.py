from __future__ import annotations
import re
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
import httpx
from core.models import Finding, Endpoint
from scanners.base_scanner import BaseScanner
from utils.payload_encoder import SSRF_PARAMS

AWS_META_PATTERNS = [
    re.compile(r"ami-[0-9a-f]{8,}", re.I),
    re.compile(r"instance-id"),
    re.compile(r"security-credentials"),
    re.compile(r"iam/security-credentials"),
    re.compile(r'"AccessKeyId"'),
    re.compile(r"169\.254\.169\.254"),
]

INTERNAL_ERROR_PATTERNS = [
    re.compile(r"Connection refused", re.I),
    re.compile(r"connect to host", re.I),
    re.compile(r"ECONNREFUSED"),
    re.compile(r"No route to host", re.I),
]


class SSRFScanner(BaseScanner):
    name = "ssrf"
    finding_type = "Server-Side Request Forgery (SSRF)"
    severity = "Critical"

    def is_applicable(self, target) -> bool:
        if isinstance(target, Endpoint):
            return any(p.lower() in SSRF_PARAMS for p in target.parameters)
        return False

    async def scan(self, target: Endpoint) -> list[Finding]:
        findings = []
        ssrf_params = [p for p in target.parameters if p.lower() in SSRF_PARAMS]

        for param in ssrf_params:
            # Test AWS metadata
            for ssrf_url in [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://127.0.0.1/",
                "http://localhost/",
            ]:
                test_url = self._inject(target.url, param, ssrf_url)
                try:
                    r = await self.session.get(test_url, timeout=8)
                    body = r.text

                    # AWS metadata found
                    for pattern in AWS_META_PATTERNS:
                        if pattern.search(body):
                            return [self.make_finding(
                                url=test_url, parameter=param, payload=ssrf_url,
                                evidence=body[:500],
                                description=f"SSRF in '{param}' — AWS metadata accessible! "
                                            f"Internal request to {ssrf_url} succeeded.",
                                remediation="Validate and whitelist allowed URLs. "
                                            "Block access to cloud metadata endpoints. "
                                            "Use IMDSv2 on AWS.",
                            )]

                    # Error-based internal discovery
                    for pattern in INTERNAL_ERROR_PATTERNS:
                        if pattern.search(body):
                            findings.append(self.make_finding(
                                url=test_url, parameter=param, payload=ssrf_url,
                                evidence=body[:300],
                                description=f"Potential SSRF in '{param}' — internal error triggered.",
                                remediation="Validate and whitelist allowed URLs.",
                            ))
                except Exception:
                    pass

        return findings

    def _inject(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
