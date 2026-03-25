"""
Active HTTP endpoint prober — discovers live API paths by probing a wordlist
of common REST endpoints against a running server.

This is the black-box counterpart to the static source-code route finder.
It is triggered automatically when Swagger/OpenAPI discovery yields no results
(e.g. when scanning a deployed API without access to its source code).
"""

import concurrent.futures
from api_pntst.utils.http_client import http_get

# ---------------------------------------------------------------------------
# Status codes that indicate a live (non-404) endpoint
# 401/403 → endpoint exists but needs auth
# 405      → endpoint exists but wrong HTTP method
# 422      → endpoint exists but validation failed
# ---------------------------------------------------------------------------
_LIVE_STATUSES = set(range(200, 400)) | {401, 403, 405, 422}

# ---------------------------------------------------------------------------
# Wordlist of common REST API endpoint paths
# ---------------------------------------------------------------------------
_COMMON_PATHS = [
    # Health & observability
    "/health",
    "/healthz",
    "/health/live",
    "/health/ready",
    "/ping",
    "/status",
    "/version",
    "/info",
    "/metrics",
    "/actuator",
    "/actuator/health",
    "/actuator/info",
    "/actuator/env",
    # API root / versioning
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    # Authentication & session
    "/auth",
    "/auth/login",
    "/auth/logout",
    "/auth/register",
    "/auth/signup",
    "/auth/token",
    "/auth/refresh",
    "/auth/me",
    "/auth/password/reset",
    "/login",
    "/logout",
    "/signup",
    "/register",
    "/token",
    "/refresh",
    "/forgot-password",
    "/reset-password",
    "/verify-email",
    "/oauth/token",
    "/oauth2/token",
    # Current user shortcuts
    "/me",
    "/profile",
    "/account",
    "/settings",
    # Common REST resources
    "/users",
    "/user",
    "/admin",
    "/roles",
    "/permissions",
    "/products",
    "/product",
    "/categories",
    "/category",
    "/items",
    "/item",
    "/orders",
    "/order",
    "/cart",
    "/checkout",
    "/payments",
    "/payment",
    "/invoices",
    "/posts",
    "/articles",
    "/comments",
    "/tags",
    "/search",
    "/notifications",
    "/messages",
    "/conversations",
    "/files",
    "/uploads",
    "/images",
    "/media",
    "/reports",
    "/analytics",
    "/events",
    "/subscriptions",
    "/webhooks",
    "/dashboard",
    # /api/v1 prefixed resources
    "/api/v1/health",
    "/api/v1/status",
    "/api/v1/me",
    "/api/v1/auth",
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/login",
    "/api/v1/register",
    "/api/v1/users",
    "/api/v1/profile",
    "/api/v1/products",
    "/api/v1/categories",
    "/api/v1/items",
    "/api/v1/orders",
    "/api/v1/posts",
    "/api/v1/search",
    "/api/v1/notifications",
    "/api/v1/files",
    "/api/v1/admin",
    # /api/v2 prefixed resources
    "/api/v2/health",
    "/api/v2/me",
    "/api/v2/users",
    "/api/v2/products",
    "/api/v2/orders",
    "/api/v2/auth",
    "/api/v2/auth/login",
    # GraphQL
    "/graphql",
    "/gql",
    "/api/graphql",
    # gRPC-gateway / misc
    "/upload",
    "/download",
    "/export",
    "/import",
    "/batch",
]


def probe_live_endpoints(
    base_url: str,
    timeout: int,
    extra_headers: dict,
    verify_ssl: bool = True,
    max_workers: int = 10,
) -> list[dict]:
    """
    Probe each path in the wordlist against *base_url*.

    Returns a list of route dicts (compatible with the scanner pipeline) for
    every path that responds with a status code indicating the endpoint exists.
    Results are returned in the same order as the wordlist.
    """
    results: dict[str, dict] = {}

    def _probe(path: str) -> tuple[str, dict | None]:
        url = base_url + path
        try:
            resp = http_get(url, timeout, extra_headers, verify_ssl)
            if resp is not None and resp.status_code in _LIVE_STATUSES:
                return path, {
                    "method": "GET",
                    "path": path,
                    "source": "probe",
                    "parameters": [],
                    "status_code": resp.status_code,
                }
        except Exception:
            pass
        return path, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_probe, path): path for path in _COMMON_PATHS}
        for future in concurrent.futures.as_completed(futures):
            path, result = future.result()
            if result:
                results[path] = result

    # Return in wordlist order for deterministic output
    return [results[p] for p in _COMMON_PATHS if p in results]
