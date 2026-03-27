from __future__ import annotations
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, urlunparse, quote
import re


def normalize_url(url: str, base: str = "") -> str:
    if not url:
        return ""
    if url.startswith("//"):
        parsed_base = urlparse(base)
        url = f"{parsed_base.scheme}:{url}"
    elif url.startswith("/") and base:
        url = urljoin(base, url)
    elif not url.startswith("http") and base:
        url = urljoin(base, url)
    try:
        parsed = urlparse(url)
        # Remove fragments
        url = urlunparse(parsed._replace(fragment=""))
    except Exception:
        pass
    return url


def extract_params(url: str) -> list[str]:
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())
    except Exception:
        return []


def inject_param(url: str, param: str, value: str) -> str:
    try:
        parsed = urlparse(url)
        from urllib.parse import parse_qs, urlencode
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    except Exception:
        return url


def same_domain(url: str, base_domain: str) -> bool:
    try:
        host = urlparse(url).netloc.lower()
        return host == base_domain or host.endswith(f".{base_domain}")
    except Exception:
        return False


def is_interesting_extension(url: str) -> bool:
    skip = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff',
            '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.pdf', '.zip',
            '.css', '.map'}
    try:
        path = urlparse(url).path.lower()
        for ext in skip:
            if path.endswith(ext):
                return False
    except Exception:
        pass
    return True
