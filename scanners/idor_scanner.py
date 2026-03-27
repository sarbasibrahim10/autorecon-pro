from __future__ import annotations
import re
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
import httpx
from core.models import Finding, Endpoint
from scanners.base_scanner import BaseScanner

ID_PARAMS = re.compile(r'^(id|user_?id|account_?id|order_?id|doc_?id|file_?id|uid|pid|cid|vid|bid)$', re.I)
NUMERIC_RE = re.compile(r'^\d+$')


class IDORScanner(BaseScanner):
    name = "idor"
    finding_type = "Insecure Direct Object Reference (IDOR)"
    severity = "High"

    def is_applicable(self, target) -> bool:
        if isinstance(target, Endpoint):
            return any(ID_PARAMS.match(p) for p in target.parameters)
        return False

    async def scan(self, target: Endpoint) -> list[Finding]:
        findings = []
        id_params = [p for p in target.parameters if ID_PARAMS.match(p)]

        for param in id_params:
            parsed = urlparse(target.url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            original_val = (qs.get(param) or ["1"])[0]

            if not NUMERIC_RE.match(str(original_val)):
                continue

            original_id = int(original_val)

            try:
                # Get baseline
                base_r = await self.session.get(target.url, timeout=10)
                base_len = len(base_r.text)
                base_status = base_r.status_code

                if base_status in (401, 403):
                    # Try bypassing with different IDs
                    for test_id in [1, 2, original_id - 1, original_id + 1]:
                        test_url = self._inject(target.url, param, str(test_id))
                        try:
                            r = await self.session.get(test_url, timeout=10)
                            if r.status_code == 200 and len(r.text) > 100:
                                findings.append(self.make_finding(
                                    url=test_url, parameter=param, payload=str(test_id),
                                    evidence=f"Original: {base_status}, Modified ({param}={test_id}): {r.status_code}",
                                    description=f"IDOR: Changing '{param}' from {original_id} to {test_id} "
                                                "bypasses access control and returns data.",
                                    remediation="Implement proper authorization checks on the server side. "
                                                "Verify the requesting user owns the resource before returning data.",
                                ))
                                break
                        except Exception:
                            continue
                elif base_status == 200:
                    # Try adjacent IDs and check for different user data
                    for test_id in [original_id - 1, original_id + 1, original_id + 100]:
                        if test_id <= 0:
                            continue
                        test_url = self._inject(target.url, param, str(test_id))
                        try:
                            r = await self.session.get(test_url, timeout=10)
                            # Same status but different content = potential IDOR
                            if r.status_code == 200 and abs(len(r.text) - base_len) > 20:
                                findings.append(self.make_finding(
                                    url=test_url, parameter=param, payload=str(test_id),
                                    evidence=f"ID={original_id}: {base_len} bytes, ID={test_id}: {len(r.text)} bytes",
                                    description=f"Potential IDOR in '{param}' — different resource returned for ID={test_id}.",
                                    remediation="Ensure server validates user owns requested resource.",
                                ))
                                break
                        except Exception:
                            continue
            except Exception:
                pass

        return findings

    def _inject(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
