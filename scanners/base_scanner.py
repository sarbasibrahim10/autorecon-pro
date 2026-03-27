from __future__ import annotations
from abc import ABC, abstractmethod
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
import httpx
from core.models import Finding, Endpoint, Subdomain


class BaseScanner(ABC):
    name: str = "base"
    severity: str = "Info"
    finding_type: str = "Base"

    def __init__(self, session: httpx.AsyncClient):
        self.session = session

    @abstractmethod
    async def scan(self, target) -> list[Finding]:
        pass

    def is_applicable(self, target) -> bool:
        return True

    def generate_poc_curl(self, url: str, method: str = "GET",
                          headers: dict | None = None, body: str = "") -> str:
        h_flags = ""
        if headers:
            for k, v in headers.items():
                h_flags += f" -H '{k}: {v}'"
        if method == "POST" and body:
            return f"curl -sk -X POST{h_flags} '{url}' --data '{body}'"
        return f"curl -sk{h_flags} '{url}'"

    def make_finding(self, *, url: str, parameter: str = "", payload: str = "",
                     evidence: str = "", description: str = "", remediation: str = "",
                     source: str = "autorecon", template_id: str = "") -> Finding:
        return Finding(
            finding_type=self.finding_type,
            severity=self.severity,
            url=url,
            parameter=parameter,
            payload=payload,
            evidence=evidence[:2000],
            poc_curl=self.generate_poc_curl(url),
            description=description,
            remediation=remediation,
            source=source,
            template_id=template_id,
        )
