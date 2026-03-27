from __future__ import annotations
import re
import httpx
from core.models import Finding, Subdomain
from scanners.base_scanner import BaseScanner

S3_LISTING = re.compile(r"<ListBucketResult", re.I)
S3_ACCESS_DENIED = re.compile(r"<Code>AccessDenied</Code>", re.I)
GCS_LISTING = re.compile(r"<ListBucketResult xmlns=", re.I)
AZURE_LISTING = re.compile(r"<EnumerationResults", re.I)


class CloudBucketScanner(BaseScanner):
    name = "cloud_buckets"
    finding_type = "Exposed Cloud Storage Bucket"
    severity = "High"

    def is_applicable(self, target) -> bool:
        return isinstance(target, Subdomain)

    async def scan(self, target: Subdomain) -> list[Finding]:
        findings = []
        domain = target.domain
        # Extract potential bucket name from domain
        bucket_candidates = self._generate_bucket_names(domain)

        for bucket in bucket_candidates:
            # AWS S3
            for s3_url in [
                f"https://{bucket}.s3.amazonaws.com/",
                f"https://s3.amazonaws.com/{bucket}/",
            ]:
                f = await self._check_s3(s3_url, bucket)
                if f:
                    findings.append(f)
                    break

            # Google Cloud Storage
            gcs_url = f"https://storage.googleapis.com/{bucket}/"
            f = await self._check_gcs(gcs_url, bucket)
            if f:
                findings.append(f)

            # Azure Blob Storage
            account = bucket.replace(".", "").replace("-", "")[:24]
            azure_url = f"https://{account}.blob.core.windows.net/{bucket}/"
            f = await self._check_azure(azure_url, bucket)
            if f:
                findings.append(f)

        return findings

    def _generate_bucket_names(self, domain: str) -> list[str]:
        parts = domain.replace(".", "-").split("-")
        base = parts[0] if parts else domain
        return list({
            domain, base,
            f"{base}-backup", f"{base}-assets", f"{base}-static",
            f"{base}-media", f"{base}-dev", f"{base}-prod",
            f"{base}-staging", f"{base}-files", f"{base}-uploads",
            f"{base}-logs", f"{base}-data",
        })[:8]

    async def _check_s3(self, url: str, bucket: str) -> Finding | None:
        try:
            r = await self.session.get(url, timeout=10)
            if r.status_code == 200 and S3_LISTING.search(r.text):
                self.severity = "High"
                return self.make_finding(
                    url=url,
                    evidence=r.text[:500],
                    description=f"AWS S3 bucket '{bucket}' is publicly readable with directory listing.",
                    remediation="Set bucket ACL to private. Enable Block Public Access settings. "
                                "Review bucket policy for overly permissive rules.",
                )
            # Check write access
            if r.status_code == 200:
                try:
                    put_r = await self.session.put(
                        url + "autorecon-test.txt",
                        content=b"autorecon-test",
                        timeout=8
                    )
                    if put_r.status_code in (200, 201):
                        self.severity = "Critical"
                        return self.make_finding(
                            url=url,
                            evidence=f"PUT to {url}autorecon-test.txt returned {put_r.status_code}",
                            description=f"AWS S3 bucket '{bucket}' allows PUBLIC WRITE ACCESS!",
                            remediation="Immediately restrict bucket write permissions.",
                        )
                except Exception:
                    pass
        except Exception:
            pass
        return None

    async def _check_gcs(self, url: str, bucket: str) -> Finding | None:
        try:
            r = await self.session.get(url, timeout=10)
            if r.status_code == 200 and GCS_LISTING.search(r.text):
                self.severity = "High"
                return self.make_finding(
                    url=url,
                    evidence=r.text[:500],
                    description=f"Google Cloud Storage bucket '{bucket}' is publicly listed.",
                    remediation="Remove allUsers and allAuthenticatedUsers from bucket IAM policy.",
                )
        except Exception:
            pass
        return None

    async def _check_azure(self, url: str, bucket: str) -> Finding | None:
        try:
            r = await self.session.get(url + "?comp=list", timeout=10)
            if r.status_code == 200 and AZURE_LISTING.search(r.text):
                self.severity = "High"
                return self.make_finding(
                    url=url,
                    evidence=r.text[:500],
                    description=f"Azure Blob container '{bucket}' is publicly accessible.",
                    remediation="Set container access level to Private in Azure portal.",
                )
        except Exception:
            pass
        return None
