from __future__ import annotations
import asyncio


async def whois_lookup(domain: str) -> dict:
    try:
        import whois
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(None, whois.whois, domain)
        return {
            "registrar": str(data.registrar or ""),
            "creation_date": str(data.creation_date or ""),
            "expiration_date": str(data.expiration_date or ""),
            "name_servers": data.name_servers or [],
        }
    except Exception:
        return {}
