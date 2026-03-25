"""Tests for scanner orchestration behavior."""

from unittest.mock import patch

from api_pntst.scanner import run_scan


@patch("api_pntst.scanner.generate_html_report")
@patch("api_pntst.scanner.print_terminal_report")
@patch("api_pntst.scanner.run_all_scanners", return_value=[])
@patch("api_pntst.scanner.find_routes", return_value=[])
@patch("api_pntst.scanner.fetch_swagger_routes", return_value=[])
@patch("api_pntst.scanner.read_env", return_value={})
def test_run_scan_uses_defaults_and_swagger_args(
    _mock_env,
    mock_fetch_swagger,
    _mock_find_routes,
    _mock_run_all,
    _mock_terminal,
    _mock_html,
):
    exit_code = run_scan(
        base_url="http://localhost:3000",
        project_dir=".",
        output_file="out.html",
        timeout=3,
        extra_headers={},
        generate_html=False,
        min_severity="info",
        concurrency=2,
        swagger_url="http://localhost:3000/openapi.json",
    )

    assert exit_code == 0
    assert mock_fetch_swagger.called
    kwargs = mock_fetch_swagger.call_args.kwargs
    assert kwargs["swagger_url"] == "http://localhost:3000/openapi.json"


@patch("api_pntst.scanner.generate_html_report")
@patch("api_pntst.scanner.print_terminal_report")
@patch("api_pntst.scanner.run_all_scanners", return_value=[])
@patch("api_pntst.scanner.find_routes", return_value=[])
@patch("api_pntst.scanner.fetch_swagger_routes", return_value=[])
@patch("api_pntst.scanner.read_env", return_value={})
def test_run_scan_code_mode_skips_swagger(
    _mock_env,
    mock_fetch_swagger,
    mock_find_routes,
    _mock_run_all,
    _mock_terminal,
    _mock_html,
):
    exit_code = run_scan(
        base_url="http://localhost:3000",
        project_dir=".",
        output_file="out.html",
        timeout=3,
        extra_headers={},
        generate_html=False,
        min_severity="info",
        concurrency=2,
        discovery_mode="code",
    )

    assert exit_code == 0
    mock_fetch_swagger.assert_not_called()
    assert mock_find_routes.called

