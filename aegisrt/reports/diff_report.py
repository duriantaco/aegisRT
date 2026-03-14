from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from aegisrt.core.diff import RunDiff, format_diff_summary
from aegisrt.core.result import TestResult


class DiffReporter:

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def report(self, diff: RunDiff) -> None:
        self._print_header(diff)
        self._print_summary_stats(diff)
        self._print_regressions(diff.new_failures)
        self._print_resolutions(diff.resolved)
        self._print_persistent(diff.persistent_failures)
        self._print_verdict(diff)

    def _print_header(self, diff: RunDiff) -> None:
        lines = [
            f"Base run:    {diff.base_run_id}",
            f"Compare run: {diff.compare_run_id}",
        ]
        panel = Panel(
            "\n".join(lines),
            title="Run Diff",
            border_style="blue",
        )
        self.console.print(panel)

    def _print_summary_stats(self, diff: RunDiff) -> None:
        s = diff.summary
        table = Table(title="Diff Summary", show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="bold")
        table.add_column("Base", justify="right")
        table.add_column("Compare", justify="right")

        table.add_row("Total tests", str(s["base_total"]), str(s["compare_total"]))
        table.add_row("Passed", str(s["base_passed"]), str(s["compare_passed"]))
        table.add_row("Failed", str(s["base_failed"]), str(s["compare_failed"]))
        table.add_row("Skipped", str(s["base_skipped"]), str(s["compare_skipped"]))
        table.add_row(
            "Pass rate",
            f"{s['base_pass_rate'] * 100:.1f}%",
            f"{s['compare_pass_rate'] * 100:.1f}%",
        )

        self.console.print(table)

        changes_table = Table(show_header=True, header_style="bold cyan")
        changes_table.add_column("Category")
        changes_table.add_column("Count", justify="right")

        changes_table.add_row(
            "[red]Regressions (new failures)[/red]",
            str(diff.regressions),
        )
        changes_table.add_row(
            "[green]Improvements (resolved)[/green]",
            str(diff.improvements),
        )
        changes_table.add_row(
            "[yellow]Persistent failures[/yellow]",
            str(len(diff.persistent_failures)),
        )
        changes_table.add_row(
            "Persistent passes",
            str(len(diff.persistent_passes)),
        )
        changes_table.add_row(
            "New passes",
            str(len(diff.new_passes)),
        )
        changes_table.add_row(
            "Skipped in compare run",
            str(len(diff.skipped)),
        )
        self.console.print(changes_table)

    def _print_regressions(self, results: list[TestResult]) -> None:
        if not results:
            return
        self.console.print("\n[bold red]Regressions (new failures)[/bold red]\n")
        table = Table(show_header=True, header_style="bold red")
        table.add_column("Probe ID", style="bold")
        table.add_column("Case ID")
        table.add_column("Severity")
        table.add_column("Score", justify="right")
        table.add_column("Confidence", justify="right")
        table.add_column("Prompt")
        table.add_column("Response")

        for r in results:
            sev_color = _severity_color(r.severity)
            table.add_row(
                r.probe_id,
                r.case_id[:12],
                f"[{sev_color}]{r.severity.upper()}[/{sev_color}]",
                f"{r.score:.2f}",
                f"{r.confidence:.2f}",
                _preview(r.input_text),
                _preview(r.response_text),
            )
        self.console.print(table)

    def _print_resolutions(self, results: list[TestResult]) -> None:
        if not results:
            return
        self.console.print("\n[bold green]Resolved[/bold green]\n")
        table = Table(show_header=True, header_style="bold green")
        table.add_column("Probe ID", style="bold")
        table.add_column("Case ID")
        table.add_column("Severity")
        table.add_column("Score", justify="right")
        table.add_column("Prompt")

        for r in results:
            sev_color = _severity_color(r.severity)
            table.add_row(
                r.probe_id,
                r.case_id[:12],
                f"[{sev_color}]{r.severity.upper()}[/{sev_color}]",
                f"{r.score:.2f}",
                _preview(r.input_text),
            )
        self.console.print(table)

    def _print_persistent(self, results: list[TestResult]) -> None:
        if not results:
            return
        self.console.print("\n[bold yellow]Persistent Failures[/bold yellow]\n")
        table = Table(show_header=True, header_style="bold yellow")
        table.add_column("Probe ID", style="bold")
        table.add_column("Case ID")
        table.add_column("Severity")
        table.add_column("Score", justify="right")
        table.add_column("Prompt")

        for r in results:
            sev_color = _severity_color(r.severity)
            table.add_row(
                r.probe_id,
                r.case_id[:12],
                f"[{sev_color}]{r.severity.upper()}[/{sev_color}]",
                f"{r.score:.2f}",
                _preview(r.input_text),
            )
        self.console.print(table)

    def _print_verdict(self, diff: RunDiff) -> None:
        if diff.regressions > 0:
            self.console.print(
                Panel(
                    f"[bold red]REGRESSIONS DETECTED: {diff.regressions} new failure(s)[/bold red]",
                    border_style="red",
                )
            )
        elif diff.improvements > 0:
            self.console.print(
                Panel(
                    f"[bold green]IMPROVED: {diff.improvements} issue(s) resolved, "
                    f"no regressions[/bold green]",
                    border_style="green",
                )
            )
        else:
            self.console.print(
                Panel(
                    "[bold]No changes between runs.[/bold]",
                    border_style="blue",
                )
            )

    def write_json(self, diff: RunDiff, path: str | Path) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        data = diff.model_dump(mode="json")
        out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return out.resolve()


def _severity_color(severity: str) -> str:
    return {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "green",
    }.get(severity.lower(), "white")


def _preview(text: str, limit: int = 48) -> str:
    if not text:
        return ""
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."
