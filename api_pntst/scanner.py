"""Main scan orchestrator — ties discovery, scanning, and reporting together."""

import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from api_pntst.discovery.env_reader import read_env
from api_pntst.discovery.route_finder import find_routes
from api_pntst.discovery.swagger_client import fetch_swagger_routes
from api_pntst.discovery.active_prober import probe_live_endpoints
from api_pntst.scanners import run_all_scanners
from api_pntst.reporters.terminal import print_terminal_report
from api_pntst.reporters.html_reporter import generate_html_report

console = Console()


def run_scan(
    base_url,
    project_dir,
    output_file,
    timeout,
    extra_headers,
    generate_html,
    min_severity,
    concurrency,
    verify_ssl=True,
    swagger_url=None,
    discovery_mode="hybrid",
):
    """
    Orchestrate the full scan lifecycle.  Returns an integer exit code
    (1 when critical/high findings are present, 0 otherwise).
    """
    project_dir = str(Path(project_dir).resolve())
    discovery_mode = (discovery_mode or "hybrid").lower()

    _print_banner()

    # ── 1. Resolve base URL ──────────────────────────────────────────────────
    console.print("\n[bold cyan]🔎 Resolving target API URL…[/]")
    env_vars = read_env(project_dir)
    resolved_url = _resolve_base_url(base_url, env_vars)

    if not resolved_url:
        console.print(
            Panel(
                "[bold red]Could not determine the target API URL.[/]\n\n"
                "Options:\n"
                "  • Pass it with [bold]--url http://localhost:3000[/]\n"
                "  • Set [bold]BASE_URL[/], [bold]API_URL[/], or [bold]PORT[/] in your [bold].env[/] file",
                title="[red]Error[/]",
                border_style="red",
            )
        )
        return 1

    console.print(f"  [green]✓[/] Target: [bold green]{resolved_url}[/]")

    # ── 2. Discover endpoints ────────────────────────────────────────────────
    console.print("\n[bold cyan]🗺  Discovering API endpoints…[/]")

    swagger_routes = []
    if discovery_mode in ("hybrid", "swagger"):
        try:
            swagger_routes = fetch_swagger_routes(
                resolved_url,
                timeout,
                extra_headers,
                verify_ssl,
                swagger_url=swagger_url,
                project_dir=project_dir,
            )
        except Exception:
            pass

    code_routes = []
    if discovery_mode in ("hybrid", "code"):
        try:
            code_routes = find_routes(project_dir)
        except Exception:
            pass

    # Active probing: when Swagger is unavailable (common for deployed APIs)
    # fall back to probing a wordlist of well-known REST paths against the
    # live server so remote-URL scans get useful coverage even without source.
    probe_routes = []
    if not swagger_routes and discovery_mode in ("hybrid", "swagger"):
        if code_routes:
            console.print(
                "  [dim]↳ No Swagger/OpenAPI spec found — "
                "tip: point [bold]--dir[/] at the project source for full coverage.[/]"
            )
        else:
            console.print(
                "  [dim]↳ No Swagger/OpenAPI spec found and no local source code — "
                "running active endpoint probing against the live API…[/]"
            )
        try:
            probe_routes = probe_live_endpoints(
                resolved_url, timeout, extra_headers, verify_ssl,
                max_workers=concurrency,
            )
        except Exception:
            pass

    endpoints = _merge_endpoints(swagger_routes, code_routes, probe_routes, resolved_url)

    if not endpoints:
        console.print(
            "  [yellow]⚠[/]  No endpoints discovered — falling back to root path only."
        )
        endpoints = [{"method": "GET", "path": "/", "url": resolved_url + "/", "source": "fallback"}]
    else:
        parts = [
            f"[bold]{len(swagger_routes)}[/] from Swagger",
            f"[bold]{len(code_routes)}[/] from source code",
        ]
        if probe_routes:
            parts.append(f"[bold]{len(probe_routes)}[/] from active probing")
        console.print(
            f"  [green]✓[/] Discovered [bold]{len(endpoints)}[/] endpoint(s) "
            f"({', '.join(parts)})"
        )

    # ── 3. Run security scanners ─────────────────────────────────────────────
    console.print("\n[bold cyan]🔍 Running security checks…[/]\n")

    auth_headers = _build_auth_headers(env_vars)
    scan_context = {
        "base_url": resolved_url,
        "endpoints": endpoints,
        "timeout": timeout,
        "extra_headers": {**auth_headers, **extra_headers},
        "env_vars": env_vars,
        "concurrency": concurrency,
        "verify_ssl": verify_ssl,
    }

    findings = run_all_scanners(scan_context)

    # ── 4. Report ────────────────────────────────────────────────────────────
    meta = {
        "target": resolved_url,
        "scanned_at": _now_iso(),
        "endpoint_count": len(endpoints),
        "project_dir": project_dir,
    }

    print_terminal_report(findings, meta, min_severity)

    if generate_html:
        console.print("\n[bold cyan]📄 Generating HTML report…[/]")
        generate_html_report(findings, endpoints, meta, output_file)
        console.print(
            f"  [green]✓[/] HTML report saved → [bold underline]{output_file}[/]"
        )

    has_critical = any(f["severity"] in ("critical", "high") for f in findings)
    return 1 if has_critical else 0


# ── Helpers ──────────────────────────────────────────────────────────────────

def _print_banner():
    banner = Text()
    banner.append("  api-pntst", style="bold cyan")
    banner.append("  —  API Penetration Testing Tool\n", style="cyan")
    banner.append("  OWASP Top-10 checks  •  Swagger discovery  •  HTML reports", style="dim")
    console.print(Panel(banner, border_style="cyan"))


def _resolve_base_url(cli_url, env_vars):
    if cli_url:
        return cli_url.rstrip("/")

    for key in ("BASE_URL", "API_URL", "APP_URL", "SERVER_URL", "BACKEND_URL"):
        if env_vars.get(key):
            return env_vars[key].rstrip("/")

    port = env_vars.get("PORT") or env_vars.get("SERVER_PORT")
    host = env_vars.get("HOST", "localhost")
    if port:
        return f"http://{host}:{port}"

    return None


def _merge_endpoints(swagger_routes, code_routes, probe_routes, base_url):
    seen = set()
    result = []
    for r in [*swagger_routes, *code_routes, *probe_routes]:
        key = f"{r['method']}:{r['path']}"
        if key in seen:
            continue
        seen.add(key)
        path = r["path"] if r["path"].startswith("/") else "/" + r["path"]
        result.append({**r, "url": base_url + path})
    return result


def _build_auth_headers(env_vars):
    for key in ("AUTH_TOKEN", "API_TOKEN", "ACCESS_TOKEN", "BEARER_TOKEN"):
        if env_vars.get(key):
            return {"Authorization": f"Bearer {env_vars[key]}"}
    for key in ("API_KEY", "X_API_KEY"):
        if env_vars.get(key):
            return {"X-Api-Key": env_vars[key]}
    return {}


def _now_iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
