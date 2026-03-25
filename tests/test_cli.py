"""Tests for CLI interactive and option forwarding behavior."""

from click.testing import CliRunner
from unittest.mock import patch

from api_pntst.cli import main


def test_interactive_requires_tty():
    runner = CliRunner()
    result = runner.invoke(main, ["--interactive"])

    assert result.exit_code != 0
    assert "requires a TTY" in result.output


def test_cli_forwards_swagger_and_discovery_mode():
    runner = CliRunner()

    with patch("api_pntst.cli.run_scan", return_value=0) as mock_run_scan:
        result = runner.invoke(
            main,
            [
                "--url",
                "http://localhost:3000",
                "--swagger-url",
                "http://localhost:3000/openapi.json",
                "--discovery-mode",
                "swagger",
                "--no-html",
            ],
        )

    assert result.exit_code == 0
    mock_run_scan.assert_called_once()
    kwargs = mock_run_scan.call_args.kwargs
    assert kwargs["base_url"] == "http://localhost:3000"
    assert kwargs["swagger_url"] == "http://localhost:3000/openapi.json"
    assert kwargs["discovery_mode"] == "swagger"
    assert kwargs["generate_html"] is False

