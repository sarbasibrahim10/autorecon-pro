from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


@dataclass
class Subdomain:
    domain: str
    ip_address: str = ""
    cname_chain: list[str] = field(default_factory=list)
    http_status: int = 0
    https_status: int = 0
    final_url: str = ""
    technologies: list[str] = field(default_factory=list)
    is_live: bool = False
    discovered_via: str = ""
    title: str = ""


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    parameters: list[str] = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    body_sample: str = ""
    source: str = "crawler"
    content_type: str = ""

    @property
    def host(self) -> str:
        from urllib.parse import urlparse
        return urlparse(self.url).netloc


@dataclass
class Finding:
    finding_type: str
    severity: str        # Critical, High, Medium, Low, Info
    url: str
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    poc_curl: str = ""
    description: str = ""
    remediation: str = ""
    source: str = "autorecon"   # autorecon | nuclei
    template_id: str = ""
    scan_id: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class ScanResult:
    scan_id: str
    target: str
    subdomains: list[Subdomain] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""
    total_requests: int = 0
