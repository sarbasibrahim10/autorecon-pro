from __future__ import annotations
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
import httpx
from core.models import Finding, Endpoint
from scanners.base_scanner import BaseScanner
from utils.payload_encoder import REDIRECT_PARAMS, OPEN_REDIRECT_PAYLOADS

EVIL_DOMAIN = "evil.com"


class OpenRedirectScanner(BaseScanner):
    name = "open_redirect"
    finding_type = "Open Redirect"
    severity = "Medium"

    def is_applicable(self, target) -> bool:
        if isinstance(target, Endpoint):
            return any(p.lower() in REDIRECT_PARAMS for p in target.parameters)
        return False

    async def scan(self, target: Endpoint) -> list[Finding]:
        findings = []
        redirect_params = [p for p in target.parameters if p.lower() in REDIRECT_PARAMS]

        # Use a no-redirect session
        no_redir_session = httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10)

        try:
            for param in redirect_params:
                for payload in OPEN_REDIRECT_PAYLOADS:
                    test_url = self._inject(target.url, param, payload)
                    try:
                        r = await no_redir_session.get(test_url)
                        if r.status_code in (301, 302, 303, 307, 308):
                            location = r.headers.get("location", "")
                            if EVIL_DOMAIN in location:
                                findings.append(self.make_finding(
                                    url=test_url, parameter=param, payload=payload,
                                    evidence=f"Location: {location}",
                                    description=f"Open Redirect in '{param}'. "
                                                f"Redirects to attacker-controlled domain.",
                                    remediation="Validate redirect URLs against a whitelist of "
                                                "allowed domains. Reject absolute URLs.",
                                ))
                                break
                    except Exception:
                        continue
        finally:
            await no_redir_session.aclose()

        return findings

    def _inject(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
