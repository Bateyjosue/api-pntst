"""Tests for scanner modules (using mocked HTTP)."""

import pytest
from unittest.mock import patch, MagicMock


def _mock_response(status=200, text="", headers=None):
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.headers = headers or {}
    return resp


class TestSecurityHeadersScanner:
    def test_flags_missing_headers(self):
        from api_pntst.scanners.security_headers import security_headers_scanner

        with patch("api_pntst.scanners.security_headers.http_get") as mock_get:
            mock_get.return_value = _mock_response(status=200, headers={})
            findings = security_headers_scanner({
                "base_url": "http://test.local",
                "timeout": 5,
                "extra_headers": {},
            })
        titles = [f["title"] for f in findings]
        assert any("Content-Security-Policy" in t for t in titles)
        assert any("Strict-Transport-Security" in t for t in titles)
        assert any("X-Frame-Options" in t for t in titles)

    def test_flags_x_powered_by(self):
        from api_pntst.scanners.security_headers import security_headers_scanner

        with patch("api_pntst.scanners.security_headers.http_get") as mock_get:
            mock_get.return_value = _mock_response(
                status=200,
                headers={"X-Powered-By": "Express"},
            )
            findings = security_headers_scanner({
                "base_url": "http://test.local",
                "timeout": 5,
                "extra_headers": {},
            })
        assert any("X-Powered-By" in f["title"] for f in findings)

    def test_no_findings_when_all_headers_present(self):
        from api_pntst.scanners.security_headers import security_headers_scanner

        good_headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
            "Cache-Control": "no-store, no-cache",
        }
        with patch("api_pntst.scanners.security_headers.http_get") as mock_get:
            mock_get.return_value = _mock_response(status=200, headers=good_headers)
            findings = security_headers_scanner({
                "base_url": "http://test.local",
                "timeout": 5,
                "extra_headers": {},
            })
        # Should have no missing-header or cache findings
        critical_missing = [
            f for f in findings
            if "Missing" in f["title"] or "Cache" in f["title"]
        ]
        assert critical_missing == []


class TestCorsScanner:
    def test_detects_wildcard_cors(self):
        from api_pntst.scanners.cors import cors_scanner

        with patch("api_pntst.scanners.cors.http_request") as mock_req:
            mock_req.return_value = _mock_response(
                status=200,
                headers={"Access-Control-Allow-Origin": "*"},
            )
            findings = cors_scanner({
                "base_url": "http://test.local",
                "endpoints": [],
                "timeout": 5,
                "extra_headers": {},
            })
        assert any("Wildcard" in f["title"] for f in findings)

    def test_detects_reflected_origin(self):
        from api_pntst.scanners.cors import cors_scanner

        def _side_effect(method, url, **kwargs):
            origin = kwargs.get("headers", {}).get("Origin", "")
            return _mock_response(
                status=200,
                headers={"Access-Control-Allow-Origin": origin},
            )

        with patch("api_pntst.scanners.cors.http_request", side_effect=_side_effect):
            findings = cors_scanner({
                "base_url": "http://test.local",
                "endpoints": [],
                "timeout": 5,
                "extra_headers": {},
            })
        assert any("Arbitrary Origin" in f["title"] for f in findings)

    def test_no_finding_when_cors_absent(self):
        from api_pntst.scanners.cors import cors_scanner

        with patch("api_pntst.scanners.cors.http_request") as mock_req:
            mock_req.return_value = _mock_response(status=200, headers={})
            findings = cors_scanner({
                "base_url": "http://test.local",
                "endpoints": [],
                "timeout": 5,
                "extra_headers": {},
            })
        assert findings == []


class TestSqlInjectionScanner:
    def test_detects_sql_error_in_response(self):
        from api_pntst.scanners.sql_injection import sql_injection_scanner

        with patch("api_pntst.scanners.sql_injection.http_request") as mock_req:
            mock_req.return_value = _mock_response(
                status=200,
                text="You have an error in your SQL syntax near '' at line 1",
            )
            findings = sql_injection_scanner({
                "endpoints": [{"method": "GET", "url": "http://test.local/users", "parameters": []}],
                "timeout": 5,
                "extra_headers": {},
            })
        assert len(findings) >= 1
        assert findings[0]["severity"] == "critical"

    def test_no_finding_on_clean_response(self):
        from api_pntst.scanners.sql_injection import sql_injection_scanner

        with patch("api_pntst.scanners.sql_injection.http_request") as mock_req:
            mock_req.return_value = _mock_response(status=200, text='{"users": []}')
            findings = sql_injection_scanner({
                "endpoints": [{"method": "GET", "url": "http://test.local/users", "parameters": []}],
                "timeout": 5,
                "extra_headers": {},
            })
        assert findings == []


class TestXssScanner:
    def test_detects_reflected_payload(self):
        from api_pntst.scanners.xss import xss_scanner

        payload = "<script>alert(1)</script>"

        def _reflect(method, url, **kwargs):
            params = kwargs.get("params", {})
            body = "&".join(f"{k}={v}" for k, v in params.items())
            return _mock_response(status=200, text=body, headers={"Content-Type": "text/html"})

        with patch("api_pntst.scanners.xss.http_request", side_effect=_reflect):
            findings = xss_scanner({
                "endpoints": [{"method": "GET", "url": "http://test.local/search", "parameters": []}],
                "timeout": 5,
                "extra_headers": {},
            })
        assert len(findings) >= 1
        assert findings[0]["severity"] == "high"

    def test_no_finding_when_payload_not_reflected(self):
        from api_pntst.scanners.xss import xss_scanner

        with patch("api_pntst.scanners.xss.http_request") as mock_req:
            mock_req.return_value = _mock_response(status=200, text="safe response")
            findings = xss_scanner({
                "endpoints": [{"method": "GET", "url": "http://test.local/search", "parameters": []}],
                "timeout": 5,
                "extra_headers": {},
            })
        assert findings == []
