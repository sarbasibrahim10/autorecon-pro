from __future__ import annotations
import asyncio
import json
from pathlib import Path
from typing import Optional
import aiosqlite
from .models import Subdomain, Endpoint, Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    status TEXT DEFAULT 'running',
    config_json TEXT
);

CREATE TABLE IF NOT EXISTS scan_phases (
    scan_id TEXT NOT NULL,
    phase TEXT NOT NULL,
    completed_at TEXT,
    PRIMARY KEY (scan_id, phase)
);

CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    subdomain TEXT NOT NULL,
    ip_address TEXT DEFAULT '',
    cname_chain TEXT DEFAULT '[]',
    http_status INTEGER DEFAULT 0,
    https_status INTEGER DEFAULT 0,
    final_url TEXT DEFAULT '',
    technologies TEXT DEFAULT '[]',
    is_live INTEGER DEFAULT 0,
    discovered_via TEXT DEFAULT '',
    title TEXT DEFAULT '',
    UNIQUE(scan_id, subdomain)
);

CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT DEFAULT 'GET',
    parameters TEXT DEFAULT '[]',
    content_type TEXT DEFAULT '',
    source TEXT DEFAULT 'crawler',
    UNIQUE(scan_id, url, method)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    url TEXT NOT NULL,
    parameter TEXT DEFAULT '',
    payload TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    poc_curl TEXT DEFAULT '',
    description TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    source TEXT DEFAULT 'autorecon',
    template_id TEXT DEFAULT '',
    discovered_at TEXT DEFAULT (datetime('now'))
);
"""


class Database:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._conn: Optional[aiosqlite.Connection] = None

    async def connect(self):
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(SCHEMA)
        await self._conn.commit()

    async def close(self):
        if self._conn:
            await self._conn.close()

    async def create_scan(self, scan_id: str, target: str, config: dict):
        from datetime import datetime
        await self._conn.execute(
            "INSERT OR IGNORE INTO scans (id, target, started_at, status, config_json) VALUES (?,?,?,?,?)",
            (scan_id, target, datetime.utcnow().isoformat(), "running", json.dumps(config))
        )
        await self._conn.commit()

    async def complete_scan(self, scan_id: str):
        from datetime import datetime
        await self._conn.execute(
            "UPDATE scans SET status='completed', completed_at=? WHERE id=?",
            (datetime.utcnow().isoformat(), scan_id)
        )
        await self._conn.commit()

    async def mark_phase_complete(self, scan_id: str, phase: str):
        from datetime import datetime
        await self._conn.execute(
            "INSERT OR REPLACE INTO scan_phases (scan_id, phase, completed_at) VALUES (?,?,?)",
            (scan_id, phase, datetime.utcnow().isoformat())
        )
        await self._conn.commit()

    async def get_completed_phases(self, scan_id: str) -> set[str]:
        async with self._conn.execute(
            "SELECT phase FROM scan_phases WHERE scan_id=?", (scan_id,)
        ) as cur:
            rows = await cur.fetchall()
        return {r["phase"] for r in rows}

    async def upsert_subdomain(self, scan_id: str, sub: Subdomain):
        await self._conn.execute("""
            INSERT INTO subdomains
                (scan_id, subdomain, ip_address, cname_chain, http_status, https_status,
                 final_url, technologies, is_live, discovered_via, title)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(scan_id, subdomain) DO UPDATE SET
                ip_address=excluded.ip_address,
                cname_chain=excluded.cname_chain,
                http_status=excluded.http_status,
                https_status=excluded.https_status,
                final_url=excluded.final_url,
                technologies=excluded.technologies,
                is_live=excluded.is_live,
                title=excluded.title
        """, (
            scan_id, sub.domain, sub.ip_address,
            json.dumps(sub.cname_chain), sub.http_status, sub.https_status,
            sub.final_url, json.dumps(sub.technologies),
            1 if sub.is_live else 0, sub.discovered_via, sub.title
        ))
        await self._conn.commit()

    async def get_subdomains(self, scan_id: str, live_only: bool = False) -> list[Subdomain]:
        query = "SELECT * FROM subdomains WHERE scan_id=?"
        if live_only:
            query += " AND is_live=1"
        async with self._conn.execute(query, (scan_id,)) as cur:
            rows = await cur.fetchall()
        result = []
        for r in rows:
            s = Subdomain(domain=r["subdomain"])
            s.ip_address = r["ip_address"]
            s.cname_chain = json.loads(r["cname_chain"])
            s.http_status = r["http_status"]
            s.https_status = r["https_status"]
            s.final_url = r["final_url"]
            s.technologies = json.loads(r["technologies"])
            s.is_live = bool(r["is_live"])
            s.title = r["title"]
            result.append(s)
        return result

    async def upsert_endpoint(self, scan_id: str, ep: Endpoint):
        await self._conn.execute("""
            INSERT OR IGNORE INTO endpoints (scan_id, url, method, parameters, content_type, source)
            VALUES (?,?,?,?,?,?)
        """, (
            scan_id, ep.url, ep.method,
            json.dumps(ep.parameters), ep.content_type, ep.source
        ))
        await self._conn.commit()

    async def get_endpoints(self, scan_id: str) -> list[Endpoint]:
        async with self._conn.execute(
            "SELECT * FROM endpoints WHERE scan_id=?", (scan_id,)
        ) as cur:
            rows = await cur.fetchall()
        result = []
        for r in rows:
            ep = Endpoint(url=r["url"], method=r["method"])
            ep.parameters = json.loads(r["parameters"])
            ep.content_type = r["content_type"]
            ep.source = r["source"]
            result.append(ep)
        return result

    async def insert_finding(self, scan_id: str, f: Finding):
        await self._conn.execute("""
            INSERT INTO findings
                (scan_id, finding_type, severity, url, parameter, payload,
                 evidence, poc_curl, description, remediation, source, template_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            scan_id, f.finding_type, f.severity, f.url, f.parameter,
            f.payload, f.evidence, f.poc_curl, f.description,
            f.remediation, f.source, f.template_id
        ))
        await self._conn.commit()

    async def get_findings(self, scan_id: str) -> list[Finding]:
        async with self._conn.execute(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY CASE severity "
            "WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 "
            "WHEN 'Low' THEN 4 ELSE 5 END", (scan_id,)
        ) as cur:
            rows = await cur.fetchall()
        result = []
        for r in rows:
            f = Finding(
                finding_type=r["finding_type"],
                severity=r["severity"],
                url=r["url"],
                parameter=r["parameter"],
                payload=r["payload"],
                evidence=r["evidence"],
                poc_curl=r["poc_curl"],
                description=r["description"],
                remediation=r["remediation"],
                source=r["source"],
                template_id=r["template_id"],
            )
            result.append(f)
        return result

    async def get_scan_stats(self, scan_id: str) -> dict:
        async with self._conn.execute(
            "SELECT COUNT(*) as total FROM subdomains WHERE scan_id=?", (scan_id,)
        ) as cur:
            total_subs = (await cur.fetchone())["total"]
        async with self._conn.execute(
            "SELECT COUNT(*) as total FROM subdomains WHERE scan_id=? AND is_live=1", (scan_id,)
        ) as cur:
            live_subs = (await cur.fetchone())["total"]
        async with self._conn.execute(
            "SELECT COUNT(*) as total FROM endpoints WHERE scan_id=?", (scan_id,)
        ) as cur:
            total_eps = (await cur.fetchone())["total"]
        async with self._conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM findings WHERE scan_id=? GROUP BY severity", (scan_id,)
        ) as cur:
            sev_rows = await cur.fetchall()
        severity_counts = {r["severity"]: r["cnt"] for r in sev_rows}
        return {
            "total_subdomains": total_subs,
            "live_subdomains": live_subs,
            "total_endpoints": total_eps,
            "severity_counts": severity_counts,
        }
