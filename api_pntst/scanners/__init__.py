"""Scanner orchestrator — runs all scanners and aggregates findings."""

from rich.console import Console

from api_pntst.scanners.sql_injection import sql_injection_scanner
from api_pntst.scanners.nosql_injection import nosql_injection_scanner
from api_pntst.scanners.xss import xss_scanner
from api_pntst.scanners.security_headers import security_headers_scanner
from api_pntst.scanners.cors import cors_scanner
from api_pntst.scanners.auth import auth_scanner
from api_pntst.scanners.sensitive_data import sensitive_data_scanner
from api_pntst.scanners.http_methods import http_methods_scanner
from api_pntst.scanners.rate_limit import rate_limit_scanner

console = Console()

_SCANNERS = [
    ("🛡  Security Headers", security_headers_scanner),
    ("🌐  CORS Configuration", cors_scanner),
    ("🔧  HTTP Methods", http_methods_scanner),
    ("🔐  Authentication", auth_scanner),
    ("💉  SQL Injection", sql_injection_scanner),
    ("🍃  NoSQL Injection", nosql_injection_scanner),
    ("⚡  XSS", xss_scanner),
    ("🔍  Sensitive Data Exposure", sensitive_data_scanner),
    ("⏱   Rate Limiting", rate_limit_scanner),
]

_SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "bold yellow",
    "medium": "bold magenta",
    "low": "bold blue",
    "info": "dim",
}


def run_all_scanners(context: dict) -> list[dict]:
    all_findings: list[dict] = []

    for name, scanner_fn in _SCANNERS:
        console.print(f"  [cyan]→[/] Running [bold]{name}[/]...", end=" ")
        try:
            findings = scanner_fn(context)
            all_findings.extend(findings)

            if not findings:
                console.print("[green]✓ No issues[/]")
            else:
                summary = _summarise(findings)
                console.print(f"[yellow]⚠[/] {summary}")
        except Exception as exc:
            console.print(f"[red]✗ Error: {exc}[/]")

    return all_findings


def _summarise(findings: list[dict]) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev):
            parts.append(f"[{_SEVERITY_COLORS[sev]}]{counts[sev]} {sev}[/]")
    return ", ".join(parts)
