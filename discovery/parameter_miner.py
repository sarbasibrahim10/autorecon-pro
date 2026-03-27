from __future__ import annotations
import asyncio
from pathlib import Path
import httpx
from core.models import Endpoint


class ParameterMiner:
    """Discover hidden parameters via wordlist fuzzing."""

    def __init__(self, session: httpx.AsyncClient):
        self.session = session
        self._wordlist: list[str] = []
        self._load_wordlist()

    def _load_wordlist(self):
        path = Path(__file__).parent.parent / "wordlists" / "parameters.txt"
        if path.exists():
            self._wordlist = [
                line.strip() for line in path.read_text().splitlines()
                if line.strip() and not line.startswith("#")
            ][:500]  # Limit to 500 for speed

    async def mine(self, endpoint: Endpoint) -> list[str]:
        if not self._wordlist:
            return []
        if endpoint.method != "GET":
            return []

        found = []
        try:
            # Baseline response
            base_r = await self.session.get(endpoint.url, timeout=10)
            base_len = len(base_r.text)

            # Batch test parameters in groups of 30
            batch_size = 30
            for i in range(0, len(self._wordlist), batch_size):
                batch = self._wordlist[i:i + batch_size]
                from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
                parsed = urlparse(endpoint.url)
                existing = parse_qs(parsed.query)
                test_params = {**existing, **{p: ["FUZZ"] for p in batch}}
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    r = await self.session.get(test_url, timeout=10)
                    # Check for significant response difference
                    if abs(len(r.text) - base_len) > 50:
                        # Find which param caused the change by testing individually
                        for param in batch:
                            individual_params = {**existing, param: ["FUZZ"]}
                            ind_query = urlencode(individual_params, doseq=True)
                            ind_url = urlunparse(parsed._replace(query=ind_query))
                            try:
                                ind_r = await self.session.get(ind_url, timeout=8)
                                if abs(len(ind_r.text) - base_len) > 30:
                                    found.append(param)
                            except Exception:
                                pass
                except Exception:
                    pass

        except Exception:
            pass
        return found
