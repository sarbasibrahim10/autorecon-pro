from __future__ import annotations
import re

SIGNATURES: dict[str, list[tuple[str, str]]] = {
    "WordPress": [("body", r"wp-content"), ("body", r"wp-includes"), ("header", r"X-Powered-By.*WordPress")],
    "Drupal": [("body", r'Drupal\.settings'), ("header", r"X-Generator.*Drupal")],
    "Joomla": [("body", r'/components/com_'), ("body", r"Joomla!")],
    "Django": [("body", r"csrfmiddlewaretoken"), ("header", r"X-Frame-Options.*SAMEORIGIN")],
    "Laravel": [("cookie", r"laravel_session"), ("header", r"X-Powered-By.*PHP")],
    "Ruby on Rails": [("header", r"X-Runtime"), ("body", r"authenticity_token")],
    "Express.js": [("header", r"X-Powered-By.*Express")],
    "ASP.NET": [("header", r"X-Powered-By.*ASP\.NET"), ("header", r"X-AspNet-Version"), ("cookie", r"ASP\.NET_SessionId")],
    "PHP": [("header", r"X-Powered-By.*PHP")],
    "Nginx": [("header", r"Server.*nginx")],
    "Apache": [("header", r"Server.*Apache")],
    "IIS": [("header", r"Server.*IIS")],
    "Cloudflare": [("header", r"CF-RAY"), ("header", r"Server.*cloudflare")],
    "AWS S3": [("body", r"<Code>NoSuchBucket</Code>"), ("header", r"x-amz-request-id")],
    "AWS ELB": [("header", r"Server.*awselb")],
    "Varnish": [("header", r"X-Varnish")],
    "React": [("body", r"__REACT_DEVTOOLS_GLOBAL_HOOK__"), ("body", r"data-reactroot")],
    "Vue.js": [("body", r"__vue__"), ("body", r"data-v-")],
    "Angular": [("body", r"ng-version"), ("body", r"_nghost")],
    "Shopify": [("body", r"Shopify\.theme"), ("header", r"X-ShopId")],
    "Stripe": [("body", r"stripe\.com/v3"), ("header", r"Stripe-Version")],
    "jQuery": [("body", r"jquery\.min\.js"), ("body", r"jQuery v")],
    "Bootstrap": [("body", r"bootstrap\.min\.css"), ("body", r"bootstrap\.min\.js")],
    "GraphQL": [("body", r'"__typename"'), ("body", r"graphql")],
    "Swagger/OpenAPI": [("body", r"swagger-ui"), ("body", r'"openapi"')],
}


def fingerprint(headers: dict, body: str) -> list[str]:
    found = []
    headers_str = " ".join(f"{k}: {v}" for k, v in headers.items())

    for tech, checks in SIGNATURES.items():
        for source, pattern in checks:
            if source == "body":
                if re.search(pattern, body, re.IGNORECASE):
                    found.append(tech)
                    break
            elif source == "header":
                if re.search(pattern, headers_str, re.IGNORECASE):
                    found.append(tech)
                    break
            elif source == "cookie":
                cookie_val = headers.get("set-cookie", "") or headers.get("Set-Cookie", "")
                if re.search(pattern, cookie_val, re.IGNORECASE):
                    found.append(tech)
                    break

    return list(set(found))
