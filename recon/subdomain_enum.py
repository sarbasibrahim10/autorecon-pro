from __future__ import annotations
import asyncio
import json
import re
from pathlib import Path
from html.parser import HTMLParser
import httpx
from core.models import Subdomain
from core.rate_limiter import RateLimiter


class SubdomainEnumerator:
    def __init__(self, domain: str, session: httpx.AsyncClient, rate_limiter: RateLimiter):
        self.domain = domain
        self.session = session
        self.rate_limiter = rate_limiter
        self._found: set[str] = set()

    async def enumerate(self) -> list[Subdomain]:
        tasks = [
            self._from_crtsh(),
            self._from_hackertarget(),
            self._from_alienvault(),
            self._from_rapiddns(),
            self._from_brute_force(),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Deduplicate
        all_subs = set()
        for r in results:
            if isinstance(r, set):
                all_subs.update(r)

        # Always include the root domain
        all_subs.add(self.domain)

        # Filter valid subdomains
        valid = {s.lower().strip() for s in all_subs
                 if s and self.domain in s and self._is_valid_domain(s)}

        return [Subdomain(domain=s, discovered_via="enum") for s in valid]

    def _is_valid_domain(self, d: str) -> bool:
        return bool(re.match(r'^[a-z0-9][a-z0-9\-\.]*\.[a-z]{2,}$', d))

    async def _from_crtsh(self) -> set[str]:
        found = set()
        try:
            await self.rate_limiter.acquire("crt.sh")
            r = await self.session.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                timeout=15
            )
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if self.domain in sub:
                            found.add(sub)
        except Exception:
            pass
        return found

    async def _from_hackertarget(self) -> set[str]:
        found = set()
        try:
            await self.rate_limiter.acquire("hackertarget.com")
            r = await self.session.get(
                f"https://api.hackertarget.com/hostsearch/?q={self.domain}",
                timeout=15
            )
            if r.status_code == 200 and "error" not in r.text.lower()[:50]:
                for line in r.text.strip().split("\n"):
                    parts = line.split(",")
                    if parts and self.domain in parts[0]:
                        found.add(parts[0].strip())
        except Exception:
            pass
        return found

    async def _from_alienvault(self) -> set[str]:
        found = set()
        try:
            await self.rate_limiter.acquire("otx.alienvault.com")
            r = await self.session.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns",
                timeout=15
            )
            if r.status_code == 200:
                data = r.json()
                for entry in data.get("passive_dns", []):
                    hostname = entry.get("hostname", "")
                    if hostname and self.domain in hostname:
                        found.add(hostname.lstrip("*."))
        except Exception:
            pass
        return found

    async def _from_rapiddns(self) -> set[str]:
        found = set()
        try:
            await self.rate_limiter.acquire("rapiddns.io")
            r = await self.session.get(
                f"https://rapiddns.io/subdomain/{self.domain}?full=1",
                timeout=15
            )
            if r.status_code == 200:
                # Extract from table
                pattern = re.compile(
                    r'<td><a[^>]*>([a-z0-9\-\.]+\.' + re.escape(self.domain) + r')</a></td>'
                )
                for match in pattern.finditer(r.text):
                    found.add(match.group(1))
        except Exception:
            pass
        return found

    async def _from_brute_force(self) -> set[str]:
        found = set()
        wordlist_path = Path(__file__).parent.parent / "wordlists" / "subdomains_small.txt"
        if not wordlist_path.exists():
            return found

        try:
            import dns.asyncresolver
            import dns.exception
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
            resolver.timeout = 2
            resolver.lifetime = 3
        except ImportError:
            return found

        words = wordlist_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        sem = asyncio.Semaphore(300)

        async def check_word(word):
            if not word or word.startswith("#"):
                return
            candidate = f"{word.strip()}.{self.domain}"
            async with sem:
                try:
                    await resolver.resolve(candidate, "A")
                    found.add(candidate)
                except Exception:
                    pass

        await asyncio.gather(*[check_word(w) for w in words[:5000]], return_exceptions=True)
        return found
