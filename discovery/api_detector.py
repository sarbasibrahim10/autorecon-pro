from __future__ import annotations
import json
import re
import httpx
from core.models import Endpoint

API_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/api-docs",
    "/api-docs.json", "/openapi.json", "/openapi.yaml",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/graphql", "/graphiql", "/api/graphql",
    "/.well-known/openid-configuration",
    "/swagger-ui/", "/swagger-ui.html",
    "/api/swagger.json", "/api/v1/swagger.json",
    "/docs/swagger.json", "/api/docs",
]

GRAPHQL_INTROSPECTION = '{"query":"{__schema{queryType{name}}}"}'


class ApiDetector:
    def __init__(self, session: httpx.AsyncClient):
        self.session = session

    async def detect(self, base_url: str) -> list[Endpoint]:
        endpoints = []
        base_url = base_url.rstrip("/")

        for path in API_PATHS:
            url = base_url + path
            try:
                r = await self.session.get(url, timeout=10)
                if r.status_code not in (200, 206):
                    continue

                ct = r.headers.get("content-type", "")
                body = r.text[:100000]

                # OpenAPI/Swagger JSON
                if "json" in ct or path.endswith(".json"):
                    try:
                        spec = r.json()
                        if "paths" in spec or "swagger" in spec or "openapi" in spec:
                            extracted = self._parse_openapi(spec, base_url)
                            endpoints.extend(extracted)
                            continue
                    except Exception:
                        pass

                # GraphQL
                if "graphql" in path.lower() or "graphql" in body.lower():
                    try:
                        r2 = await self.session.post(
                            url,
                            content=GRAPHQL_INTROSPECTION,
                            headers={"Content-Type": "application/json"},
                            timeout=10
                        )
                        if r2.status_code == 200 and "__schema" in r2.text:
                            endpoints.append(Endpoint(url=url, method="POST", source="api_graphql"))
                    except Exception:
                        pass

                # Generic — add the discovered spec URL
                endpoints.append(Endpoint(url=url, source="api_spec"))

            except Exception:
                continue

        return endpoints

    def _parse_openapi(self, spec: dict, base_url: str) -> list[Endpoint]:
        endpoints = []
        paths = spec.get("paths", {})
        servers = spec.get("servers", [{"url": base_url}])
        server_url = servers[0].get("url", base_url) if servers else base_url

        if not server_url.startswith("http"):
            server_url = base_url

        for path, methods in paths.items():
            for method, detail in methods.items():
                if method.lower() not in ("get", "post", "put", "patch", "delete"):
                    continue
                params = [
                    p.get("name", "") for p in detail.get("parameters", [])
                    if p.get("name")
                ]
                ep = Endpoint(
                    url=server_url.rstrip("/") + path,
                    method=method.upper(),
                    parameters=params,
                    source="api_openapi"
                )
                endpoints.append(ep)
        return endpoints
