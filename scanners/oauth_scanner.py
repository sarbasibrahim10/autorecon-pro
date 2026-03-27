from __future__ import annotations
import re
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.models import Finding, Endpoint
from scanners.base_scanner import BaseScanner

OAUTH_PATHS = [
    "/oauth/authorize", "/oauth/token", "/oauth2/authorize", "/oauth2/token",
    "/auth/authorize", "/connect/authorize", "/o/oauth2/auth",
    "/.well-known/openid-configuration",
]

REDIRECT_URI_PATTERN = re.compile(r'redirect_uri', re.I)
STATE_PATTERN = re.compile(r'[?&]state=', re.I)
RESPONSE_TYPE_TOKEN = re.compile(r'response_type=token', re.I)


class OAuthScanner(BaseScanner):
    name = "oauth"
    finding_type = "OAuth Misconfiguration"
    severity = "High"

    def is_applicable(self, target) -> bool:
        if isinstance(target, Endpoint):
            url_lower = target.url.lower()
            return any(path in url_lower for path in OAUTH_PATHS) or \
                   any(p in ("redirect_uri", "client_id", "response_type", "code") for p in target.parameters)
        return False

    async def scan(self, target: Endpoint) -> list[Finding]:
        findings = []
        url_lower = target.url.lower()

        # 1. OpenID Configuration exposure
        if ".well-known/openid-configuration" in url_lower:
            try:
                r = await self.session.get(target.url, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    findings.append(self.make_finding(
                        url=target.url,
                        severity_override="Info",
                        evidence=str(list(data.keys()))[:300],
                        description="OpenID Connect configuration endpoint exposed — reveals authorization/token endpoints.",
                        remediation="This is expected but ensure all endpoints are secured properly.",
                    ))
            except Exception:
                pass

        # 2. Implicit flow detection
        if RESPONSE_TYPE_TOKEN.search(target.url):
            findings.append(self.make_finding(
                url=target.url,
                evidence=f"URL contains: response_type=token",
                description="OAuth implicit flow detected (response_type=token). "
                            "Implicit flow is deprecated in OAuth 2.1 and leaks tokens in browser history.",
                remediation="Use Authorization Code flow with PKCE instead of implicit flow.",
            ))

        # 3. Missing state parameter (CSRF)
        if any(p == "redirect_uri" for p in target.parameters):
            if "state" not in target.parameters:
                findings.append(self.make_finding(
                    url=target.url,
                    parameter="state",
                    evidence="redirect_uri present but 'state' parameter absent",
                    description="OAuth flow missing 'state' parameter — vulnerable to CSRF attacks. "
                                "Attacker can initiate OAuth flow on behalf of victim.",
                    remediation="Always include a cryptographically random 'state' parameter and validate it on callback.",
                ))

        # 4. Open redirect in redirect_uri
        if "redirect_uri" in target.parameters:
            for evil_uri in ["https://evil.com", "//evil.com", "https://evil.com%2F"]:
                test_url = self._inject(target.url, "redirect_uri", evil_uri)
                try:
                    no_redir = httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10)
                    r = await no_redir.get(test_url)
                    await no_redir.aclose()
                    if r.status_code in (301, 302, 303, 307, 308):
                        loc = r.headers.get("location", "")
                        if "evil.com" in loc:
                            findings.append(self.make_finding(
                                url=test_url,
                                parameter="redirect_uri",
                                payload=evil_uri,
                                evidence=f"Redirected to: {loc}",
                                description="OAuth redirect_uri validation bypassed — code/token will be sent to attacker.",
                                remediation="Strictly validate redirect_uri against a pre-registered whitelist.",
                            ))
                            break
                except Exception:
                    pass

        return findings

    def _inject(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

    def make_finding(self, *, severity_override: str = None, **kwargs) -> Finding:
        orig = self.severity
        if severity_override:
            self.severity = severity_override
        f = super().make_finding(**kwargs)
        self.severity = orig
        return f
