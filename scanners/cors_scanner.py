from __future__ import annotations
from urllib.parse import urlparse
import httpx
from core.models import Finding, Endpoint
from scanners.base_scanner import BaseScanner


class CORSScanner(BaseScanner):
    name = "cors"
    finding_type = "CORS Misconfiguration"
    severity = "High"

    def is_applicable(self, target) -> bool:
        return isinstance(target, Endpoint)

    async def scan(self, target: Endpoint) -> list[Finding]:
        findings = []
        parsed = urlparse(target.url)
        host = parsed.netloc

        test_origins = [
            "https://evil.com",
            f"https://{host}.evil.com",
            "null",
            f"https://evil{host}",
            f"https://{parsed.scheme}evil.com",
        ]

        for origin in test_origins:
            try:
                r = await self.session.get(
                    target.url,
                    headers={"Origin": origin},
                    timeout=10
                )
                acao = r.headers.get("access-control-allow-origin", "")
                acac = r.headers.get("access-control-allow-credentials", "").lower()

                if not acao:
                    continue

                severity = "Info"
                description = ""

                if acao == origin and acac == "true":
                    severity = "Critical"
                    description = (
                        f"Critical CORS: Origin '{origin}' reflected with credentials allowed. "
                        "Attacker can make credentialed cross-origin requests."
                    )
                elif acao == "null" and acac == "true":
                    severity = "High"
                    description = "CORS null origin accepted with credentials — exploitable via sandboxed iframe."
                elif acao == "*" and acac == "true":
                    severity = "High"
                    description = "CORS wildcard with credentials (spec violation but some browsers allow it)."
                elif acao == origin:
                    severity = "Medium"
                    description = f"CORS: arbitrary origin '{origin}' reflected (no credentials)."
                elif acao == "*":
                    severity = "Low"
                    description = "CORS wildcard — allows any origin to read responses (no credentials)."

                if description:
                    self.severity = severity
                    findings.append(self.make_finding(
                        url=target.url,
                        evidence=f"ACAO: {acao}\nACAC: {acac}",
                        description=description,
                        remediation="Whitelist specific trusted origins. Never reflect arbitrary origins. "
                                    "Do not combine wildcard ACAO with credentials.",
                    ))
                    break  # One finding per endpoint is enough

            except Exception:
                continue

        return findings
