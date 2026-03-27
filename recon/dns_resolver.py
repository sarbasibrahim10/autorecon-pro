from __future__ import annotations
import asyncio
from core.models import Subdomain

try:
    import dns.asyncresolver
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


class DNSResolver:
    NAMESERVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

    def __init__(self):
        if HAS_DNSPYTHON:
            self._resolver = dns.asyncresolver.Resolver()
            self._resolver.nameservers = self.NAMESERVERS
            self._resolver.timeout = 3
            self._resolver.lifetime = 5

    async def resolve(self, subdomain: Subdomain) -> Subdomain:
        if not HAS_DNSPYTHON:
            return subdomain
        domain = subdomain.domain
        try:
            # A record
            try:
                a_answers = await self._resolver.resolve(domain, "A")
                subdomain.ip_address = str(a_answers[0])
            except Exception:
                pass

            # CNAME chain
            try:
                cname_chain = []
                current = domain
                for _ in range(10):
                    try:
                        cname_ans = await self._resolver.resolve(current, "CNAME")
                        target = str(cname_ans[0]).rstrip(".")
                        cname_chain.append(target)
                        current = target
                    except Exception:
                        break
                subdomain.cname_chain = cname_chain
            except Exception:
                pass

        except Exception:
            pass
        return subdomain

    async def is_nxdomain(self, domain: str) -> bool:
        if not HAS_DNSPYTHON:
            return False
        try:
            await self._resolver.resolve(domain, "A")
            return False
        except dns.resolver.NXDOMAIN:
            return True
        except Exception:
            return False
