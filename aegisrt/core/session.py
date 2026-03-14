from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from aegisrt.core.result import RunReport, TestResult

class Session:

    def __init__(self, output_dir: str = ".aegisrt", run_id: str | None = None) -> None:
        self.run_id: str = run_id or uuid.uuid4().hex[:12]
        self.output_dir = Path(output_dir)
        self.start_time: datetime | None = None
        self.end_time: datetime | None = None
        self._results: list[TestResult] = []

    @property
    def results(self) -> list[TestResult]:
        return list(self._results)

    def start(self) -> None:
        self.start_time = datetime.now(timezone.utc)

    def add_result(self, result: TestResult) -> None:
        self._results.append(result)

    def finish(self) -> RunReport:
        self.end_time = datetime.now(timezone.utc)

        total = len(self._results)
        passed = sum(1 for r in self._results if r.passed)
        failed = total - passed

        summary = {
            "total": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": round(passed / total, 4) if total else 1.0,
            "duration_seconds": self._elapsed_seconds(),
        }

        return RunReport(
            run_id=self.run_id,
            timestamp=self.start_time.isoformat() if self.start_time else "",
            results=self._results,
            summary=summary,
        )

    def save_artifacts(self, report: RunReport) -> Path:
        run_dir = self.output_dir / "runs" / self.run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        report_path = run_dir / "report.json"
        report_path.write_text(
            report.model_dump_json(indent=2),
            encoding="utf-8",
        )

        latest_path = self.output_dir / "latest.json"
        latest_path.write_text(
            json.dumps({"run_id": self.run_id, "path": str(report_path)}),
            encoding="utf-8",
        )

        return report_path

    def _elapsed_seconds(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0
