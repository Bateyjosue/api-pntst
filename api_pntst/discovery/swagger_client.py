"""
Fetches Swagger / OpenAPI documentation from well-known paths and extracts
routes from the spec.

Returns a list of dicts compatible with the rest of the scanner pipeline.
"""

import json
import re
from api_pntst.utils.http_client import http_get

_SWAGGER_PATHS = [
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/api-docs.json",
    "/openapi.json",
    "/openapi.yaml",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v3/swagger.json",
    "/docs/swagger.json",
    "/api/swagger.json",
    "/api/docs",
    "/docs/openapi.json",
]

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def fetch_swagger_routes(base_url: str, timeout: int, extra_headers: dict, verify_ssl: bool = True) -> list[dict]:
    """Try each well-known Swagger path; return routes from the first valid spec found."""
    for path in _SWAGGER_PATHS:
        url = base_url + path
        try:
            resp = http_get(url, timeout, extra_headers, verify_ssl)
            if resp is None or resp.status_code >= 400:
                continue

            spec = _parse_spec(resp)
            if not spec:
                continue

            routes = _extract_routes(spec)
            if routes:
                from rich.console import Console
                Console().print(
                    f"  [dim]↳ Swagger spec found at {url} "
                    f"([bold]{len(routes)}[/] routes)[/]"
                )
                return routes
        except Exception:
            continue

    return []


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_spec(response) -> dict | None:
    content_type = response.headers.get("Content-Type", "")
    text = response.text

    if "json" in content_type or text.lstrip().startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

    # Minimal YAML parsing — extract paths and HTTP methods only
    return _parse_yaml_spec(text)


def _parse_yaml_spec(yaml_text: str) -> dict | None:
    """Very lightweight YAML parser — only extracts the `paths` section."""
    paths: dict = {}
    current_path: str | None = None

    for line in yaml_text.splitlines():
        # Top-level path entries (0–2 spaces of indent, starts with /)
        path_match = re.match(r"^\s{0,2}(\/[^:]+):\s*$", line)
        if path_match:
            current_path = path_match.group(1).strip()
            paths[current_path] = {}
            continue

        if current_path:
            method_match = re.match(r"^\s{4,6}(get|post|put|patch|delete|head|options)\s*:", line, re.IGNORECASE)
            if method_match:
                paths[current_path][method_match.group(1)] = {}

    return {"paths": paths} if paths else None


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
