from __future__ import annotations
import random
import string
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
import httpx
from core.models import Finding, Endpoint
from scanners.base_scanner import BaseScanner
from utils.payload_encoder import XSS_PAYLOADS

CANARY_LEN = 8
XSS_SIGNS = ["<script>", "onerror=", "onload=", "alert(1)", "svg/onload", "<img src=x"]


class XSSScanner(BaseScanner):
    name = "xss"
    finding_type = "Cross-Site Scripting (XSS)"
    severity = "High"

    def is_applicable(self, target) -> bool:
        if isinstance(target, Endpoint):
            return bool(target.parameters) or target.method == "POST"
        return False

    async def scan(self, target: Endpoint) -> list[Finding]:
        findings = []
        params = target.parameters or []

        for param in params:
            # Step 1: canary reflection test
            canary = "xss" + "".join(random.choices(string.ascii_lowercase, k=CANARY_LEN))
            test_url = self._inject(target.url, param, canary)
            try:
                r = await self.session.get(test_url, timeout=10, follow_redirects=True)
                if canary not in r.text:
                    continue
                # Reflected! Now try payloads
                for payload in XSS_PAYLOADS:
                    attack_url = self._inject(target.url, param, payload)
                    try:
                        r2 = await self.session.get(attack_url, timeout=10, follow_redirects=True)
                        body = r2.text
                        if any(sign in body for sign in XSS_SIGNS):
                            snippet = self._extract_snippet(body, payload)
                            f = self.make_finding(
                                url=attack_url,
                                parameter=param,
                                payload=payload,
                                evidence=snippet,
                                description=f"Reflected XSS in parameter '{param}'. "
                                            f"The payload '{payload}' was reflected unencoded in the response.",
                                remediation="Encode all user input before rendering in HTML. "
                                            "Implement a Content Security Policy.",
                            )
                            f.poc_curl = self.generate_poc_curl(attack_url)
                            findings.append(f)
                            break
                    except Exception:
                        continue
            except Exception:
                continue
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
        start = max(0, idx - 100)
        end = min(len(body), idx + len(payload) + 100)
        return "..." + body[start:end] + "..."
