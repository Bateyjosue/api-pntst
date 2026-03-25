"""Tests for Swagger/OpenAPI discovery and parsing."""

from unittest.mock import MagicMock, patch

from api_pntst.discovery.swagger_client import fetch_swagger_routes


def _resp(status=200, text="", content_type="application/json"):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {"Content-Type": content_type}
    return r


def test_prefers_direct_swagger_url_when_provided():
    spec_json = '{"openapi":"3.0.0","paths":{"/users":{"get":{"summary":"List users"}}}}'

    def _side_effect(url, *_args, **_kwargs):
        if url == "https://docs.example.com/openapi.json":
            return _resp(text=spec_json)
        return _resp(status=404, text="not found")

    with patch("api_pntst.discovery.swagger_client.http_get", side_effect=_side_effect):
        routes = fetch_swagger_routes(
            base_url="https://api.example.com",
            timeout=5,
            extra_headers={},
            verify_ssl=True,
            swagger_url="https://docs.example.com/openapi.json",
        )

    assert len(routes) == 1
    assert routes[0]["method"] == "GET"
    assert routes[0]["path"] == "/users"


def test_extracts_spec_url_from_swagger_ui_html():
    docs_html = '<html><script>window.ui=SwaggerUIBundle({url:"/openapi.json"})</script></html>'
    spec_json = '{"openapi":"3.0.0","paths":{"/health":{"get":{}}}}'

    def _side_effect(url, *_args, **_kwargs):
        if url == "https://api.example.com/docs":
            return _resp(text=docs_html, content_type="text/html")
        if url == "https://api.example.com/openapi.json":
            return _resp(text=spec_json)
        return _resp(status=404, text="not found")

    with patch("api_pntst.discovery.swagger_client.http_get", side_effect=_side_effect):
        routes = fetch_swagger_routes(
            base_url="https://api.example.com",
            timeout=5,
            extra_headers={},
            verify_ssl=True,
            swagger_url="https://api.example.com/docs",
        )

    assert len(routes) == 1
    assert routes[0]["path"] == "/health"


def test_falls_back_to_local_openapi_file_when_remote_unavailable(tmp_path):
    local_spec = tmp_path / "openapi.yaml"
    local_spec.write_text(
        """
openapi: 3.0.0
info:
  title: Demo
  version: 1.0.0
paths:
  /status:
    get:
      summary: Status
""".strip(),
        encoding="utf-8",
    )

    with patch("api_pntst.discovery.swagger_client.http_get", return_value=None):
        routes = fetch_swagger_routes(
            base_url="https://api.example.com",
            timeout=5,
            extra_headers={},
            verify_ssl=True,
            project_dir=str(tmp_path),
        )

    assert len(routes) == 1
    assert routes[0]["method"] == "GET"
    assert routes[0]["path"] == "/status"

