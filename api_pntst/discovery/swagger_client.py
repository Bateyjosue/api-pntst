"""
Fetches Swagger / OpenAPI documentation from well-known paths and extracts
routes from the spec.

Returns a list of dicts compatible with the rest of the scanner pipeline.
"""

import json
import re
from pathlib import Path
from urllib.parse import urljoin

import yaml
from openapi_spec_validator import validate
from openapi_spec_validator.validation.exceptions import OpenAPIValidationError
from api_pntst.utils.http_client import http_get

_SWAGGER_PATHS = [
    # Generic OpenAPI / Swagger
    "/swagger.json",
    "/swagger.yaml",
    "/openapi.json",
    "/openapi.yaml",
    # Swagger UI default paths
    "/api-docs",
    "/api-docs.json",
    "/api-docs.yaml",
    # Versioned generic paths
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v3/swagger.json",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/v3/openapi.json",
    # Spring Boot (springdoc-openapi / springfox)
    "/v2/api-docs",
    "/v3/api-docs",
    "/v3/api-docs.yaml",
    "/api/v2/api-docs",
    "/api/v3/api-docs",
    # NestJS / common /api prefix
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/openapi.yaml",
    "/api/docs",
    "/api/swagger",
    # /docs prefix (FastAPI default, Django Spectacular, etc.)
    "/docs/swagger.json",
    "/docs/openapi.json",
    "/docs/openapi.yaml",
    # Hono, tRPC and other modern stacks
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    # Well-known
    "/.well-known/openapi.json",
    "/.well-known/openapi.yaml",
    # Config directory paths
    "/config/swagger.json",
    "/config/openapi.json",
    "/config/api-docs.json",
    "/config/swagger.yaml",
    "/config/openapi.yaml",
]

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
_SWAGGER_UI_PATHS = ["/docs", "/swagger", "/swagger-ui", "/api/docs", "/api/swagger"]
_LOCAL_SPEC_GLOBS = ["**/openapi*.json", "**/openapi*.y*ml", "**/swagger*.json", "**/swagger*.y*ml"]
_MAX_LOCAL_FILES = 20
_HTML_SPEC_PATTERNS = [
    re.compile(r"url\s*:\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"\"url\"\s*:\s*\"([^\"]+)\"", re.IGNORECASE),
    re.compile(r"\"urls\"\s*:\s*\[(.*?)\]", re.IGNORECASE | re.DOTALL),
]


def fetch_swagger_routes(
    base_url: str,
    timeout: int,
    extra_headers: dict,
    verify_ssl: bool = True,
    swagger_url: str | None = None,
    project_dir: str | None = None,
) -> list[dict]:
    """Discover and parse OpenAPI routes from direct URL, remote probing, or local files."""
    candidates = []
    if swagger_url:
        candidates.append(swagger_url.strip())
    candidates.extend(base_url + p for p in _SWAGGER_PATHS)
    candidates.extend(base_url + p for p in _SWAGGER_UI_PATHS)

    for candidate in candidates:
        routes = _fetch_routes_from_url(candidate, timeout, extra_headers, verify_ssl)
        if routes:
            return routes

    if project_dir:
        return _fetch_routes_from_local_spec(project_dir)

    return []


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _fetch_routes_from_url(url: str, timeout: int, extra_headers: dict, verify_ssl: bool) -> list[dict]:
    try:
        resp = http_get(url, timeout, extra_headers, verify_ssl)
        if resp is None or resp.status_code >= 400:
            return []

        content_type = (resp.headers.get("Content-Type", "") or "").lower()
        text = resp.text or ""

        if "html" in content_type or text.lstrip().lower().startswith("<!doctype") or "<html" in text[:300].lower():
            for spec_url in _extract_spec_urls_from_html(url, text):
                routes = _fetch_routes_from_url(spec_url, timeout, extra_headers, verify_ssl)
                if routes:
                    return routes
            return []

        spec = _parse_spec_text(content_type, text)
        if not spec:
            return []

        routes = _extract_routes(spec)
        if routes:
            from rich.console import Console
            Console().print(
                f"  [dim]↳ Swagger/OpenAPI spec found at {url} "
                f"([bold]{len(routes)}[/] routes)[/]"
            )
            return routes
    except Exception:
        return []

    return []


def _fetch_routes_from_local_spec(project_dir: str) -> list[dict]:
    root = Path(project_dir)
    if not root.exists():
        return []

    matched = []
    for pattern in _LOCAL_SPEC_GLOBS:
        matched.extend(root.glob(pattern))

    for path in sorted(set(matched))[:_MAX_LOCAL_FILES]:
        if not path.is_file():
            continue
        try:
            spec = _parse_spec_text("", path.read_text(encoding="utf-8", errors="ignore"))
            if not spec:
                continue
            routes = _extract_routes(spec)
            if routes:
                from rich.console import Console
                Console().print(
                    f"  [dim]↳ OpenAPI spec loaded from local file {path} "
                    f"([bold]{len(routes)}[/] routes)[/]"
                )
                return routes
        except OSError:
            continue

    return []


def _parse_spec_text(content_type: str, text: str) -> dict | None:
    spec = None

    if "json" in content_type or text.lstrip().startswith("{"):
        try:
            spec = json.loads(text)
        except json.JSONDecodeError:
            spec = None

    if spec is None:
        try:
            loaded = yaml.safe_load(text)
            if isinstance(loaded, dict):
                spec = loaded
        except yaml.YAMLError:
            spec = None

    if not isinstance(spec, dict):
        return None

    try:
        validate(spec)
    except OpenAPIValidationError:
        # Keep scanning even when the spec is non-compliant but still usable.
        pass
    except Exception:
        pass

    return spec if isinstance(spec.get("paths"), dict) else None


def _extract_spec_urls_from_html(page_url: str, html_text: str) -> list[str]:
    urls: set[str] = set()

    for pattern in _HTML_SPEC_PATTERNS[:2]:
        for match in pattern.finditer(html_text):
            urls.add(urljoin(page_url, match.group(1).strip()))

    for match in _HTML_SPEC_PATTERNS[2].finditer(html_text):
        for inner in re.finditer(r"\"url\"\s*:\s*\"([^\"]+)\"", match.group(1), re.IGNORECASE):
            urls.add(urljoin(page_url, inner.group(1).strip()))

    return list(urls)


def _extract_routes(spec: dict) -> list[dict]:
    routes: list[dict] = []
    paths = spec.get("paths", {})

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            if method.lower() not in _HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                operation = {}
            routes.append(
                {
                    "method": method.upper(),
                    "path": path,
                    "source": "swagger",
                    "summary": operation.get("summary", ""),
                    "operation_id": operation.get("operationId", ""),
                    "parameters": operation.get("parameters", []),
                    "request_body": operation.get("requestBody"),
                    "security": operation.get("security"),
                    "tags": operation.get("tags", []),
                }
            )
    return routes
