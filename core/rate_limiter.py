from __future__ import annotations
import asyncio
import time
from collections import defaultdict


class RateLimiter:
    """Token-bucket rate limiter per domain."""

    def __init__(self, requests_per_second: float = 10.0):
        self.rps = requests_per_second
        self._tokens: dict[str, float] = defaultdict(lambda: requests_per_second)
        self._last_refill: dict[str, float] = defaultdict(time.monotonic)
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def acquire(self, domain: str = "global"):
        async with self._locks[domain]:
            now = time.monotonic()
            elapsed = now - self._last_refill[domain]
            self._tokens[domain] = min(
                self.rps, self._tokens[domain] + elapsed * self.rps
            )
            self._last_refill[domain] = now

            if self._tokens[domain] < 1.0:
                wait = (1.0 - self._tokens[domain]) / self.rps
                await asyncio.sleep(wait)
                self._tokens[domain] = 0.0
            else:
                self._tokens[domain] -= 1.0
