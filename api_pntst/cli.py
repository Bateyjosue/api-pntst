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
    "--swagger-url",
    default=None,
    help="Direct URL to OpenAPI/Swagger spec (json/yaml).",
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
@click.option(
    "--discovery-mode",
    type=click.Choice(["hybrid", "swagger", "code"], case_sensitive=False),
    default="hybrid",
    show_default=True,
    help="Endpoint discovery strategy.",
)
@click.option(
    "--interactive",
    is_flag=True,
    default=False,
    help="Run an interactive setup to choose scan options.",
)
def main(
    url,
    swagger_url,
    project_dir,
    output,
    timeout,
    headers,
    no_html,
    severity,
    insecure,
    concurrency,
    discovery_mode,
    interactive,
):
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
    if interactive:
        if not sys.stdin.isatty():
            raise click.ClickException("--interactive requires a TTY.")
        (
            url,
            swagger_url,
            project_dir,
            output,
            timeout,
            no_html,
            severity,
            insecure,
            concurrency,
            discovery_mode,
        ) = _interactive_options(
            url,
            swagger_url,
            project_dir,
            output,
            timeout,
            no_html,
            severity,
            insecure,
            concurrency,
            discovery_mode,
        )

    extra_headers = _parse_headers(headers)
    exit_code = run_scan(
        base_url=url,
        swagger_url=swagger_url,
        project_dir=project_dir,
        output_file=output,
        timeout=timeout,
        extra_headers=extra_headers,
        generate_html=not no_html,
        min_severity=severity,
        verify_ssl=not insecure,
        concurrency=concurrency,
        discovery_mode=discovery_mode.lower(),
    )
    sys.exit(exit_code)


def _parse_headers(raw_headers):
    result = {}
    for h in raw_headers:
        idx = h.find(":")
        if idx > 0:
            result[h[:idx].strip()] = h[idx + 1:].strip()
    return result


def _interactive_options(
    url,
    swagger_url,
    project_dir,
    output,
    timeout,
    no_html,
    severity,
    insecure,
    concurrency,
    discovery_mode,
):
    click.echo("\napi-pntst interactive setup")
    click.echo("Press Enter to accept defaults.\n")

    url = click.prompt(
        "Target API base URL (leave empty to auto-detect from .env)",
        default=url or "",
        show_default=False,
    ).strip() or None

    swagger_url = click.prompt(
        "Swagger/OpenAPI URL (optional)",
        default=swagger_url or "",
        show_default=False,
    ).strip() or None

    discovery_mode = click.prompt(
        "Discovery mode",
        type=click.Choice(["hybrid", "swagger", "code"], case_sensitive=False),
        default=discovery_mode,
        show_default=True,
    ).lower()

    project_dir = click.prompt("Project directory", default=project_dir, show_default=True)
    output = click.prompt("Output HTML report", default=output, show_default=True)
    timeout = click.prompt("HTTP timeout (seconds)", type=int, default=timeout, show_default=True)
    concurrency = click.prompt("Concurrency", type=int, default=concurrency, show_default=True)
    severity = click.prompt(
        "Minimum terminal severity",
        type=click.Choice(["critical", "high", "medium", "low", "info"], case_sensitive=False),
        default=severity,
        show_default=True,
    ).lower()
    no_html = not click.confirm("Generate HTML report?", default=not no_html)
    insecure = click.confirm("Disable SSL verification?", default=insecure)

    return (
        url,
        swagger_url,
        project_dir,
        output,
        timeout,
        no_html,
        severity,
        insecure,
        concurrency,
        discovery_mode,
    )

