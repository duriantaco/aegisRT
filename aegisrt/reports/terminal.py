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
        self._print_inconclusive_warning(run_report)
        self._print_resistance_profile(run_report)
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

    def _print_inconclusive_warning(self, report: RunReport) -> None:
        inconclusive = [
            r for r in report.results if r.evidence.get("inconclusive")
        ]
        if not inconclusive:
            return

        affected_probes = sorted({r.probe_id for r in inconclusive})
        panel = Panel(
            f"[bold]{len(inconclusive)}[/bold] result(s) across "
            f"[bold]{len(affected_probes)}[/bold] probe(s) could not be "
            f"evaluated because the judge LLM was unreachable.\n"
            f"Affected probes: {', '.join(affected_probes)}\n\n"
            f"These results are marked [bold]FAIL[/bold] (fail-safe). "
            f"Configure a working judge provider to get real verdicts.\n"
            f"Set [bold]providers.judge.api_key[/bold] and "
            f"[bold]providers.judge.base_url[/bold] in your config.",
            title="Inconclusive Results",
            border_style="bold yellow",
        )
        self.console.print(panel)

    def _print_resistance_profile(self, report: RunReport) -> None:
        profile = report.summary.get("resistance_profile")
        if not profile or not profile.get("by_technique"):
            return

        grade = profile.get("overall_grade", "unknown")
        score = profile.get("overall_score", 0.0)
        grade_colors = {
            "excellent": "bold green",
            "good": "green",
            "fair": "yellow",
            "poor": "red",
            "critical": "bold red",
        }
        gc = grade_colors.get(grade, "white")

        table = Table(
            title=f"Resistance Profile  [{gc}]{grade.upper()} ({score * 100:.1f}%)[/{gc}]",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Technique", min_width=20)
        table.add_column("Tests", justify="right", width=6)
        table.add_column("Pass", justify="right", width=6)
        table.add_column("Fail", justify="right", width=6)
        table.add_column("Rate", justify="right", width=8)
        table.add_column("", width=12)

        by_tech = profile["by_technique"]
        sorted_techs = sorted(
            by_tech.items(), key=lambda x: x[1]["pass_rate"]
        )

        for tech_id, info in sorted_techs:
            rate = info["pass_rate"]
            if rate >= 0.95:
                color = "green"
                bar = "[green]" + "█" * 10 + "[/green]"
            elif rate >= 0.80:
                color = "green"
                filled = round(rate * 10)
                bar = f"[green]{'█' * filled}[/green]{'░' * (10 - filled)}"
            elif rate >= 0.60:
                color = "yellow"
                filled = round(rate * 10)
                bar = f"[yellow]{'█' * filled}[/yellow]{'░' * (10 - filled)}"
            else:
                color = "red"
                filled = round(rate * 10)
                bar = f"[red]{'█' * filled}[/red]{'░' * (10 - filled)}"

            table.add_row(
                info["name"],
                str(info["total"]),
                str(info["passed"]),
                str(info["failed"]),
                f"[{color}]{rate * 100:.0f}%[/{color}]",
                bar,
            )

        self.console.print(table)

        weakest = profile.get("weakest", [])
        if weakest and weakest[0]["pass_rate"] < 1.0:
            weak_names = [w["name"] for w in weakest if w["pass_rate"] < 1.0]
            if weak_names:
                self.console.print(
                    f"  [bold yellow]Prioritize defenses for:[/bold yellow] "
                    f"{', '.join(weak_names[:3])}"
                )
                self.console.print()

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
