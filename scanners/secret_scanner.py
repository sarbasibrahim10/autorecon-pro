from __future__ import annotations
import re
from pathlib import Path
import httpx
from core.models import Finding, Endpoint
from scanners.base_scanner import BaseScanner

BUILTIN_PATTERNS = {
    "AWS Access Key": (re.compile(r"AKIA[0-9A-Z]{16}"), "Critical"),
    "AWS Secret Key": (re.compile(r'(?i)aws.{0,20}secret.{0,20}["\'][0-9a-zA-Z/+]{40}["\']'), "Critical"),
    "GitHub Token (classic)": (re.compile(r"ghp_[0-9a-zA-Z]{36}"), "High"),
    "GitHub Token (fine-grained)": (re.compile(r"github_pat_[0-9a-zA-Z_]{82}"), "High"),
    "Google API Key": (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "High"),
    "Stripe Secret Key": (re.compile(r"sk_live_[0-9a-zA-Z]{24}"), "Critical"),
    "Stripe Publishable Key": (re.compile(r"pk_live_[0-9a-zA-Z]{24}"), "Medium"),
    "Private RSA Key": (re.compile(r"-----BEGIN RSA PRIVATE KEY-----"), "Critical"),
    "Private EC Key": (re.compile(r"-----BEGIN EC PRIVATE KEY-----"), "Critical"),
    "Private Key (generic)": (re.compile(r"-----BEGIN (?:PRIVATE|OPENSSH) KEY-----"), "Critical"),
    "JWT Token": (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "Medium"),
    "Basic Auth in URL": (re.compile(r"https?://[^:@\s]+:[^@\s]+@"), "High"),
    "DB Connection String": (re.compile(r"(mysql|postgres|mongodb|redis)://[^:]+:[^@]+@"), "High"),
    "SendGrid API Key": (re.compile(r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"), "High"),
    "Slack Token": (re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"), "High"),
    "Slack Webhook": (re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"), "High"),
    "Twilio API Key": (re.compile(r"SK[0-9a-fA-F]{32}"), "High"),
    "NPM Token": (re.compile(r"npm_[A-Za-z0-9]{36}"), "High"),
    "Generic API Key": (re.compile(r'(?i)(api_key|apikey|api-key)["\'\s:=]+["\'][0-9a-zA-Z]{16,}["\']'), "Medium"),
    "Generic Secret": (re.compile(r'(?i)(secret|password|passwd|pwd)["\'\s:=]+["\'][^"\']{8,}["\']'), "Medium"),
    "Hardcoded Password": (re.compile(r'(?i)password\s*=\s*["\'][^"\']{6,}["\']'), "Medium"),
}


class SecretScanner(BaseScanner):
    name = "secrets"
    finding_type = "Exposed Secret / Credential"
    severity = "High"

    def is_applicable(self, target) -> bool:
        return isinstance(target, Endpoint)

    async def scan(self, target: Endpoint) -> list[Finding]:
        findings = []
        try:
            r = await self.session.get(target.url, timeout=12)
            body = r.text[:500000]

            for secret_type, (pattern, severity) in BUILTIN_PATTERNS.items():
                m = pattern.search(body)
                if m:
                    matched = m.group(0)[:100]
                    # Basic deduplication: skip if looks like an example
                    if "example" in matched.lower() or "placeholder" in matched.lower():
                        continue
                    self.severity = severity
                    self.finding_type = f"Exposed {secret_type}"
                    findings.append(self.make_finding(
                        url=target.url,
                        evidence=f"Found {secret_type}: {matched[:50]}...",
                        description=f"Hardcoded {secret_type} found in page content. "
                                    f"Exposing credentials allows account takeover or resource abuse.",
                        remediation=f"Remove the {secret_type} from the source code. "
                                    "Rotate the credential immediately. "
                                    "Store secrets in environment variables or a secrets manager.",
                    ))

        except Exception:
            pass
        return findings
