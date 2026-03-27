from __future__ import annotations
from datetime import datetime
from core.database import Database


class ReportBuilder:
    def __init__(self, db: Database, scan_id: str):
        self.db = db
        self.scan_id = scan_id

    async def build(self) -> dict:
        findings = await self.db.get_findings(self.scan_id)
        subdomains = await self.db.get_subdomains(self.scan_id)
        endpoints = await self.db.get_endpoints(self.scan_id)
        stats = await self.db.get_scan_stats(self.scan_id)

        # Severity counts
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for sev, cnt in stats.get("severity_counts", {}).items():
            if sev in sev_counts:
                sev_counts[sev] = cnt

        # Finding type distribution
        type_dist: dict[str, int] = {}
        for f in findings:
            t = f.finding_type.split("]")[-1].strip() if "[Nuclei]" in f.finding_type else f.finding_type
            # Group by base type
            base = t.split("(")[0].strip()[:30]
            type_dist[base] = type_dist.get(base, 0) + 1

        # Findings per subdomain
        sub_findings: dict[str, int] = {}
        for f in findings:
            from urllib.parse import urlparse
            host = urlparse(f.url).netloc or f.url[:30]
            sub_findings[host] = sub_findings.get(host, 0) + 1

        # Top 10 subdomains by findings
        top_subs = sorted(sub_findings.items(), key=lambda x: x[1], reverse=True)[:10]

        # Serialise findings
        findings_data = []
        for i, f in enumerate(findings):
            findings_data.append({
                "id": i + 1,
                "type": f.finding_type,
                "severity": f.severity,
                "url": f.url,
                "parameter": f.parameter,
                "payload": f.payload[:100] if f.payload else "",
                "evidence": f.evidence[:500] if f.evidence else "",
                "poc_curl": f.poc_curl,
                "description": f.description,
                "remediation": f.remediation,
                "source": f.source,
                "template_id": f.template_id,
            })

        # Serialise subdomains
        subs_data = []
        for s in sorted(subdomains, key=lambda x: (not x.is_live, x.domain)):
            subs_data.append({
                "domain": s.domain,
                "ip": s.ip_address,
                "status": s.https_status or s.http_status,
                "is_live": s.is_live,
                "technologies": s.technologies,
                "title": s.title,
                "findings_count": sub_findings.get(s.domain, 0),
            })

        async with self.db._conn.execute(
            "SELECT target, started_at, completed_at FROM scans WHERE id=?", (self.scan_id,)
        ) as cur:
            row = await cur.fetchone()

        return {
            "scan_id": self.scan_id,
            "target": row["target"] if row else "",
            "started_at": row["started_at"] if row else "",
            "completed_at": row["completed_at"] or datetime.utcnow().isoformat(),
            "severity_counts": sev_counts,
            "type_distribution": type_dist,
            "top_subdomains_by_findings": top_subs,
            "total_subdomains": stats["total_subdomains"],
            "live_subdomains": stats["live_subdomains"],
            "total_endpoints": stats["total_endpoints"],
            "total_findings": len(findings),
            "findings": findings_data,
            "subdomains": subs_data,
            "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
