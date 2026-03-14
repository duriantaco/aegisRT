from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from aegisrt.core.result import RunReport, TestResult


class TerminalReporter:

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def report(self, run_report: RunReport, duration_seconds: float = 0.0) -> None:
        self._print_header(run_report, duration_seconds)
        self._print_summary_table(run_report)
        self._print_metrics(run_report)
        failed = [r for r in run_report.results if not r.passed]
        if failed:
            self._print_failed_findings(failed)
        self._print_verdict(run_report)

    def _print_header(self, report: RunReport, duration_seconds: float) -> None:
        meta_lines = [
            f"Run ID:    {report.run_id}",
            f"Timestamp: {report.timestamp}",
            f"Duration:  {duration_seconds:.2f}s",
        ]
        if report.target_info:
            target_type = report.target_info.get("type", "unknown")
            meta_lines.append(f"Target:    {target_type}")
        panel = Panel(
            "\n".join(meta_lines),
            title="AegisRT Security Test Report",
            border_style="blue",
        )
        self.console.print(panel)

    def _print_summary_table(self, report: RunReport) -> None:
        counts = self._count_by_severity(report.results)
        table = Table(title="Summary by Severity", show_header=True, header_style="bold cyan")
        table.add_column("Severity", style="bold")
        table.add_column("Total", justify="right")
        table.add_column("Passed", justify="right", style="green")
        table.add_column("Failed", justify="right", style="red")

        for sev in ("critical", "high", "medium", "low"):
            info = counts.get(sev, {"total": 0, "passed": 0, "failed": 0})
            if info["total"] == 0:
                continue
            table.add_row(
                sev.upper(),
                str(info["total"]),
                str(info["passed"]),
                str(info["failed"]),
            )

        total_passed = sum(1 for r in report.results if r.passed)
        total_failed = len(report.results) - total_passed
        table.add_row(
            "TOTAL",
            str(len(report.results)),
            str(total_passed),
            str(total_failed),
            style="bold",
        )
        self.console.print(table)

    def _print_metrics(self, report: RunReport) -> None:
        metrics = report.metrics
        if not metrics or not metrics.get("total_calls"):
            return

        total_calls = metrics.get("total_calls", 0)
        total_latency = metrics.get("total_latency_ms", 0.0)
        avg_latency = metrics.get("avg_latency_ms", 0.0)
        max_latency = metrics.get("max_latency_ms", 0.0)
        total_tokens = metrics.get("total_tokens", 0)
        total_cost = metrics.get("total_cost_usd", 0.0)

        lines = [
            f"Total calls      : {total_calls}",
            f"Total latency    : {total_latency:.1f}ms",
            f"Avg latency      : {avg_latency:.1f}ms",
            f"Max latency      : {max_latency:.1f}ms",
            f"Total tokens     : {total_tokens:,}",
            f"Estimated cost   : ${total_cost:.6f}",
        ]

        panel = Panel(
            "\n".join(lines),
            title="Metrics",
            border_style="dim",
        )
        self.console.print(panel)

    def _print_failed_findings(self, failed: list[TestResult]) -> None:
        self.console.print("\n[bold red]Failed Findings[/bold red]\n")
        for result in failed:
            sev_color = self._severity_color(result.severity)
            self.console.print(
                f"  [{sev_color}]{result.severity.upper()}[/{sev_color}] "
                f"[bold]{result.probe_id}[/bold] "
                f"(confidence: {result.confidence:.2f}, score: {result.score:.2f})"
            )
            if result.evidence:
                snippet = self._format_evidence(result.evidence)
                self.console.print(f"    Evidence: {snippet}")
            if result.remediation:
                self.console.print("    Remediation:")
                for step in result.remediation:
                    self.console.print(f"      - {step}")
            self.console.print()

    def _print_verdict(self, report: RunReport) -> None:
        any_failed = any(not r.passed for r in report.results)
        if any_failed:
            verdict = Text("FAIL", style="bold white on red")
        else:
            verdict = Text("PASS", style="bold white on green")
        self.console.print()
        self.console.print(Panel(verdict, title="Verdict", border_style="bold"))

    @staticmethod
    def _count_by_severity(results: list[TestResult]) -> dict[str, dict[str, int]]:
        counts: dict[str, dict[str, int]] = {}
        for r in results:
            sev = r.severity.lower()
            if sev not in counts:
                counts[sev] = {"total": 0, "passed": 0, "failed": 0}
            counts[sev]["total"] += 1
            if r.passed:
                counts[sev]["passed"] += 1
            else:
                counts[sev]["failed"] += 1
        return counts

    @staticmethod
    def _severity_color(severity: str) -> str:
        return {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "green",
        }.get(severity.lower(), "white")

    @staticmethod
    def _format_evidence(evidence: dict[str, Any], max_len: int = 200) -> str:
        parts: list[str] = []
        if "detections" in evidence:
            triggered = [d for d in evidence["detections"] if d.get("triggered")]
            parts.append(f"{len(triggered)} detectors triggered")
        if "max_score" in evidence:
            parts.append(f"max_score={evidence['max_score']:.2f}")
        if "response" in evidence:
            resp_len = evidence["response"].get("response_length", "?")
            parts.append(f"response_len={resp_len}")
        if parts:
            text = ", ".join(parts)
        else:
            text = str(evidence)
        if len(text) > max_len:
            text = text[: max_len - 3] + "..."
        return text
