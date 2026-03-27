from __future__ import annotations
import re
import httpx
from core.models import Endpoint
from utils.url_utils import extract_params


class WaybackFetcher:
    CDX_URL = "http://web.archive.org/cdx/search/cdx"

    def __init__(self, session: httpx.AsyncClient):
        self.session = session

    async def fetch(self, domain: str) -> list[Endpoint]:
        endpoints = []
        try:
            params = {
                "url": f"*.{domain}",
                "output": "json",
                "fl": "original",
                "collapse": "urlkey",
                "limit": "5000",
                "filter": "statuscode:200",
            }
            r = await self.session.get(self.CDX_URL, params=params, timeout=30)
            if r.status_code != 200:
                return []

            data = r.json()
            seen = set()
            for row in data[1:]:  # Skip header row
                url = row[0] if row else ""
                if not url or url in seen:
                    continue
                seen.add(url)
                params_list = extract_params(url)
                endpoints.append(Endpoint(url=url, parameters=params_list, source="wayback"))

        except Exception:
            pass
        return endpoints
