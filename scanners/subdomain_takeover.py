from __future__ import annotations
import asyncio
import httpx
from core.models import Finding, Subdomain
from scanners.base_scanner import BaseScanner

# service CNAME pattern → fingerprint string on their "not found" page
TAKEOVER_FINGERPRINTS = {
    "github.io": "There isn't a GitHub Pages site here",
    "amazonaws.com": "NoSuchBucket",
    "s3.amazonaws.com": "NoSuchBucket",
    "azurewebsites.net": "404 Web Site not found",
    "cloudapp.net": "404 Web Site not found",
    "trafficmanager.net": "404 Web Site not found",
    "blob.core.windows.net": "BlobNotFound",
    "table.core.windows.net": "TableNotFound",
    "queue.core.windows.net": "QueueNotFound",
    "file.core.windows.net": "ShareNotFound",
    "herokuapp.com": "No such app",
    "herokussl.com": "No such app",
    "shopify.com": "Sorry, this shop is currently unavailable",
    "myshopify.com": "Sorry, this shop is currently unavailable",
    "fastly.net": "Fastly error: unknown domain",
    "zendesk.com": "Help Center Closed",
    "surge.sh": "project not found",
    "readme.io": "Project doesnt exist",
    "ghost.io": "The thing you were looking for is no longer here",
    "helpscoutdocs.com": "No settings were found for this company",
    "intercom.io": "This page is reserved for artistic dogs",
    "bitbucket.io": "Repository not found",
    "strikingly.com": "page not found",
    "webflow.io": "The page you are looking for doesn't exist",
    "wordpress.com": "Do you want to register",
    "tumblr.com": "There's nothing here",
    "squarespace.com": "No Such Account",
    "tilda.ws": "Please renew your subscription",
    "netlify.com": "Not Found - Request ID",
    "netlify.app": "Not Found - Request ID",
    "vercel.app": "The deployment could not be found",
    "pages.dev": "not found",
}


class SubdomainTakeoverScanner(BaseScanner):
    name = "subdomain_takeover"
    finding_type = "Subdomain Takeover"
    severity = "High"

    def is_applicable(self, target) -> bool:
        return isinstance(target, Subdomain)

    async def scan(self, target: Subdomain) -> list[Finding]:
        findings = []
        if not target.cname_chain:
            return findings

        # Check each CNAME in chain against fingerprints
        for cname in target.cname_chain:
            cname_lower = cname.lower()
            for service_pattern, fingerprint in TAKEOVER_FINGERPRINTS.items():
                if service_pattern in cname_lower:
                    # Try to fetch the subdomain and check for fingerprint
                    for url in [f"https://{target.domain}", f"http://{target.domain}"]:
                        try:
                            r = await self.session.get(url, timeout=10)
                            if fingerprint.lower() in r.text.lower():
                                findings.append(self.make_finding(
                                    url=url,
                                    evidence=f"CNAME chain: {' → '.join(target.cname_chain)}\n"
                                             f"Service: {service_pattern}\n"
                                             f"Fingerprint found: '{fingerprint}'",
                                    description=f"Subdomain takeover possible on {target.domain}. "
                                                f"CNAME points to {cname} ({service_pattern}) "
                                                f"which shows unclaimed resource fingerprint.",
                                    remediation=f"Either remove the DNS record for {target.domain} "
                                                f"or claim the resource on {service_pattern}.",
                                ))
                                break
                        except Exception:
                            pass
                    break

        return findings
