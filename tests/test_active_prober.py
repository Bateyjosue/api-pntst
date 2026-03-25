"""Tests for the active endpoint prober."""

from unittest.mock import patch, MagicMock


def _mock_response(status=200):
    resp = MagicMock()
    resp.status_code = status
    return resp


class TestActiveProber:
    _base_ctx = {
        "base_url": "http://test.local",
        "timeout": 5,
        "extra_headers": {},
    }

    def test_includes_live_200_endpoints(self):
        from api_pntst.discovery.active_prober import probe_live_endpoints

        with patch("api_pntst.discovery.active_prober.http_get") as mock_get:
            def _side_effect(url, *args, **kwargs):
                if url.endswith("/health"):
                    return _mock_response(200)
                return _mock_response(404)

            mock_get.side_effect = _side_effect
            results = probe_live_endpoints("http://test.local", 5, {})

        paths = [r["path"] for r in results]
        assert "/health" in paths

    def test_includes_401_endpoints(self):
        """Endpoints returning 401 exist but require auth — should be included."""
        from api_pntst.discovery.active_prober import probe_live_endpoints

        with patch("api_pntst.discovery.active_prober.http_get") as mock_get:
            def _side_effect(url, *args, **kwargs):
                if url.endswith("/users"):
                    return _mock_response(401)
                return _mock_response(404)

            mock_get.side_effect = _side_effect
            results = probe_live_endpoints("http://test.local", 5, {})

        paths = [r["path"] for r in results]
        assert "/users" in paths

    def test_includes_403_endpoints(self):
        """Endpoints returning 403 exist but access is denied — should be included."""
        from api_pntst.discovery.active_prober import probe_live_endpoints

        with patch("api_pntst.discovery.active_prober.http_get") as mock_get:
            def _side_effect(url, *args, **kwargs):
                if url.endswith("/admin"):
                    return _mock_response(403)
                return _mock_response(404)

            mock_get.side_effect = _side_effect
            results = probe_live_endpoints("http://test.local", 5, {})

        paths = [r["path"] for r in results]
        assert "/admin" in paths

    def test_excludes_404_endpoints(self):
        from api_pntst.discovery.active_prober import probe_live_endpoints

        with patch("api_pntst.discovery.active_prober.http_get") as mock_get:
            mock_get.return_value = _mock_response(404)
            results = probe_live_endpoints("http://test.local", 5, {})

        assert results == []

    def test_excludes_500_endpoints(self):
        """500 errors mean the server is broken, not that the endpoint meaningfully exists."""
        from api_pntst.discovery.active_prober import probe_live_endpoints

        with patch("api_pntst.discovery.active_prober.http_get") as mock_get:
            mock_get.return_value = _mock_response(500)
            results = probe_live_endpoints("http://test.local", 5, {})

        assert results == []

    def test_handles_exceptions_gracefully(self):
        """Network errors for individual paths should not propagate."""
        from api_pntst.discovery.active_prober import probe_live_endpoints

        with patch("api_pntst.discovery.active_prober.http_get") as mock_get:
            mock_get.side_effect = ConnectionError("refused")
            results = probe_live_endpoints("http://test.local", 5, {})

        assert results == []

    def test_result_has_expected_structure(self):
        from api_pntst.discovery.active_prober import probe_live_endpoints

        with patch("api_pntst.discovery.active_prober.http_get") as mock_get:
            def _side_effect(url, *args, **kwargs):
                if url.endswith("/ping"):
                    return _mock_response(200)
                return _mock_response(404)

            mock_get.side_effect = _side_effect
            results = probe_live_endpoints("http://test.local", 5, {})

        assert len(results) >= 1
        hit = next(r for r in results if r["path"] == "/ping")
        assert hit["method"] == "GET"
        assert hit["source"] == "probe"
        assert isinstance(hit["parameters"], list)

    def test_deduplication_in_scanner_merge(self):
        """Active-probe results that overlap with code routes should be deduplicated."""
        from api_pntst.scanner import _merge_endpoints

        code = [{"method": "GET", "path": "/health", "source": "code", "parameters": []}]
        probe = [{"method": "GET", "path": "/health", "source": "probe", "parameters": []}]
        merged = _merge_endpoints([], code, probe, "http://test.local")

        health_endpoints = [e for e in merged if e["path"] == "/health"]
        assert len(health_endpoints) == 1  # no duplicates

    def test_probe_routes_added_to_merged_endpoints(self):
        """Probe-only routes not in swagger or code should appear in merged output."""
        from api_pntst.scanner import _merge_endpoints

        probe = [{"method": "GET", "path": "/metrics", "source": "probe", "parameters": []}]
        merged = _merge_endpoints([], [], probe, "http://test.local")

        paths = [e["path"] for e in merged]
        assert "/metrics" in paths
        assert merged[0]["url"] == "http://test.local/metrics"

    def test_deduplication_across_all_three_sources(self):
        """When all three sources share the same endpoint, only one copy appears."""
        from api_pntst.scanner import _merge_endpoints

        swagger = [{"method": "GET", "path": "/health", "source": "swagger", "parameters": []}]
        code = [{"method": "GET", "path": "/health", "source": "code", "parameters": []}]
        probe = [{"method": "GET", "path": "/health", "source": "probe", "parameters": []}]
        merged = _merge_endpoints(swagger, code, probe, "http://test.local")

        health_hits = [e for e in merged if e["path"] == "/health"]
        assert len(health_hits) == 1
        # Swagger takes priority (it is first in the merge list)
        assert health_hits[0]["source"] == "swagger"
