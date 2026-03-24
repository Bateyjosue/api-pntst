"""CLI entry point for api-pntst."""

import sys
import click
from api_pntst.scanner import run_scan


@click.command()
@click.version_option("1.0.0", prog_name="api-pntst")
@click.option(
    "-u", "--url",
    default=None,
    help="Base URL of the target API (overrides .env detection).",
)
@click.option(
    "-d", "--dir",
    "project_dir",
    default=".",
    show_default=True,
    help="Project directory to scan for routes and .env files.",
)
@click.option(
    "-o", "--output",
    default="api-pntst-report.html",
    show_default=True,
    help="Output HTML report file path.",
)
@click.option(
    "-t", "--timeout",
    default=8,
    show_default=True,
    type=int,
    help="HTTP request timeout in seconds.",
)
@click.option(
    "-H", "--header",
    "headers",
    multiple=True,
    help='Extra request header in "Key: Value" format (can be repeated).',
)
@click.option(
    "--no-html",
    is_flag=True,
    default=False,
    help="Skip HTML report generation.",
)
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low", "info"], case_sensitive=False),
    default="info",
    show_default=True,
    help="Minimum severity level to display in terminal output.",
)
@click.option(
    "--insecure",
    is_flag=True,
    default=False,
    help="Disable SSL certificate verification (useful for dev/self-signed certs).",
)
@click.option(
    "--concurrency",
    default=5,
    show_default=True,
    type=int,
    help="Number of concurrent scan threads.",
)
def main(url, project_dir, output, timeout, headers, no_html, severity, insecure, concurrency):
    """
    \b
    api-pntst — API Penetration Testing Tool
    ─────────────────────────────────────────
    Discovers API routes and Swagger docs, runs OWASP Top-10
    security checks, and produces a rich HTML report.

    \b
    Examples:
      api-pntst --url http://localhost:3000
      api-pntst --dir /path/to/project --output report.html
      api-pntst --url https://api.example.com --severity high
    """
    extra_headers = _parse_headers(headers)
    exit_code = run_scan(
        base_url=url,
        project_dir=project_dir,
        output_file=output,
        timeout=timeout,
        extra_headers=extra_headers,
        generate_html=not no_html,
        min_severity=severity,
        verify_ssl=not insecure,
        concurrency=concurrency,
    )
    sys.exit(exit_code)


def _parse_headers(raw_headers):
    result = {}
    for h in raw_headers:
        idx = h.find(":")
        if idx > 0:
            result[h[:idx].strip()] = h[idx + 1:].strip()
    return result
