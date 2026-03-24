"""Terminal reporter — prints a rich, colour-coded summary of findings."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "bold blue",
    "info": "dim",
}
_MIN_SEVERITY_IDX = {s: i for i, s in enumerate(_SEVERITY_ORDER)}


def print_terminal_report(findings: list[dict], meta: dict, min_severity: str = "info"):
    """Print the full terminal report."""
    min_idx = _MIN_SEVERITY_IDX.get(min_severity.lower(), 4)
    visible = [f for f in findings if _MIN_SEVERITY_IDX.get(f["severity"], 4) <= min_idx]

    _print_summary(findings, meta)

    if not visible:
        console.print(
            Panel(
                "[bold green]No findings at or above the selected severity level.[/]",
                border_style="green",
            )
        )
        return

    _print_findings_table(visible)
    _print_findings_detail(visible)


def _print_summary(findings: list[dict], meta: dict):
    counts = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        if f["severity"] in counts:
            counts[f["severity"]] += 1

    total = sum(counts.values())
    scanned_at = meta.get("scanned_at", "")[:19].replace("T", " ")

    summary = Text()
    summary.append(f"\n  Target:     ", style="bold")
    summary.append(meta.get("target", "-"), style="cyan")
    summary.append(f"\n  Scanned at: ", style="bold")
    summary.append(scanned_at, style="dim")
    summary.append(f"\n  Endpoints:  ", style="bold")
    summary.append(str(meta.get("endpoint_count", 0)))
    summary.append(f"\n  Total findings: ", style="bold")
    summary.append(str(total), style="bold" if total else "green")

    for sev in _SEVERITY_ORDER:
        if counts[sev]:
            summary.append(f"\n    {sev.capitalize():10}", style="bold")
            summary.append(str(counts[sev]), style=_SEVERITY_STYLE[sev])

    console.print(Panel(summary, title="[bold cyan]Scan Summary[/]", border_style="cyan"))


def _print_findings_table(findings: list[dict]):
    table = Table(
        title="[bold]Findings Overview[/]",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Scanner", width=22)
    table.add_column("Endpoint", overflow="fold", max_width=45)
    table.add_column("Title", overflow="fold")

    sorted_findings = sorted(
        findings,
        key=lambda f: _MIN_SEVERITY_IDX.get(f["severity"], 99),
    )

    for i, f in enumerate(sorted_findings, 1):
        sev = f["severity"]
        table.add_row(
            str(i),
            Text(sev.upper(), style=_SEVERITY_STYLE.get(sev, "")),
            f.get("scanner", ""),
            f.get("endpoint", ""),
            f.get("title", ""),
        )

    console.print()
    console.print(table)


def _print_findings_detail(findings: list[dict]):
    sorted_findings = sorted(
        findings,
        key=lambda f: _MIN_SEVERITY_IDX.get(f["severity"], 99),
    )

    console.print("\n[bold cyan]Detailed Findings[/]\n")

    for i, f in enumerate(sorted_findings, 1):
        sev = f["severity"]
        border = {"critical": "red", "high": "yellow", "medium": "magenta", "low": "blue"}.get(sev, "white")

        detail = Text()
        detail.append(f"  Severity:    ", style="bold")
        detail.append(sev.upper(), style=_SEVERITY_STYLE.get(sev, ""))
        detail.append(f"\n  Scanner:     ", style="bold")
        detail.append(f.get("scanner", ""))
        detail.append(f"\n  Endpoint:    ", style="bold")
        detail.append(f.get("endpoint", ""), style="cyan")
        detail.append(f"\n\n  Description:\n  ", style="bold")
        detail.append(f.get("description", ""))

        if f.get("evidence"):
            detail.append(f"\n\n  Evidence:\n  ", style="bold")
            detail.append(f.get("evidence", ""), style="dim")

        detail.append(f"\n\n  Remediation:\n  ", style="bold green")
        detail.append(f.get("remediation", ""))

        refs = f.get("references", [])
        if refs:
            detail.append(f"\n\n  References:", style="bold")
            for ref in refs:
                detail.append(f"\n    • {ref}", style="underline blue")

        console.print(
            Panel(
                detail,
                title=f"[bold]#{i} — {f.get('title', '')}[/]",
                border_style=border,
                padding=(0, 1),
            )
        )
        console.print()
