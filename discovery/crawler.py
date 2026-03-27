from __future__ import annotations
import asyncio
import re
from collections import deque
from html.parser import HTMLParser
from urllib.parse import urlparse, urljoin
import httpx
from core.models import Endpoint
from core.rate_limiter import RateLimiter
from utils.url_utils import normalize_url, extract_params, same_domain, is_interesting_extension


class LinkExtractor(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "a" and "href" in attrs_dict:
            self.links.append(normalize_url(attrs_dict["href"], self.base_url))
        elif tag == "script" and "src" in attrs_dict:
            self.links.append(normalize_url(attrs_dict["src"], self.base_url))
        elif tag == "link" and "href" in attrs_dict:
            self.links.append(normalize_url(attrs_dict["href"], self.base_url))
        elif tag == "form":
            self._current_form = {
                "action": normalize_url(attrs_dict.get("action", self.base_url), self.base_url),
                "method": attrs_dict.get("method", "GET").upper(),
                "inputs": []
            }
        elif tag == "input" and self._current_form is not None:
            name = attrs_dict.get("name")
            if name:
                self._current_form["inputs"].append(name)
        elif tag == "img" and "src" in attrs_dict:
            self.links.append(normalize_url(attrs_dict["src"], self.base_url))

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form:
            self.forms.append(self._current_form)
            self._current_form = None


class Crawler:
    def __init__(self, session: httpx.AsyncClient, rate_limiter: RateLimiter, config):
        self.session = session
        self.rate_limiter = rate_limiter
        self.max_depth = config.max_crawl_depth
        self.max_urls = config.max_urls_per_host
        self.timeout = config.timeout

    async def crawl(self, start_url: str) -> list[Endpoint]:
        if not start_url or not start_url.startswith("http"):
            return []

        parsed = urlparse(start_url)
        base_domain = parsed.netloc
        visited: set[str] = set()
        endpoints: list[Endpoint] = []
        queue = deque([(start_url, 0)])

        while queue and len(visited) < self.max_urls:
            url, depth = queue.popleft()
            if url in visited or depth > self.max_depth:
                continue
            if not is_interesting_extension(url):
                continue

            visited.add(url)
            try:
                await self.rate_limiter.acquire(base_domain)
                r = await self.session.get(url, timeout=self.timeout)
                params = extract_params(url)
                ct = r.headers.get("content-type", "")
                ep = Endpoint(
                    url=url, method="GET", parameters=params,
                    content_type=ct, source="crawler"
                )
                endpoints.append(ep)

                if "text/html" in ct or "javascript" in ct:
                    extractor = LinkExtractor(url)
                    extractor.feed(r.text[:200000])

                    for link in extractor.links:
                        if link and same_domain(link, base_domain) and link not in visited:
                            if link.startswith("http"):
                                queue.append((link, depth + 1))

                    for form in extractor.forms:
                        form_ep = Endpoint(
                            url=form["action"],
                            method=form["method"],
                            parameters=form["inputs"],
                            source="crawler"
                        )
                        endpoints.append(form_ep)

            except Exception:
                pass

        return endpoints
