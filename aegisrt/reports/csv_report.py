from __future__ import annotations

import csv
import json
from pathlib import Path

from aegisrt.core.result import RunReport, TestResult

DEFAULT_COLUMNS = [
    "case_id",
    "probe_id",
    "passed",
    "score",
    "severity",
    "confidence",
    "evidence_summary",
    "remediation",
]

ALL_COLUMNS = [
    "case_id",
    "probe_id",
    "input_text",
    "response_text",
    "passed",
    "score",
    "severity",
    "confidence",
    "evidence_summary",
    "remediation",
]


def _evidence_summary(evidence: dict) -> str:
    parts: list[str] = []
    if "detections" in evidence:
        triggered = [d for d in evidence["detections"] if d.get("triggered")]
        parts.append(f"{len(triggered)} detectors triggered")
    if "max_score" in evidence:
        parts.append(f"max_score={evidence['max_score']:.2f}")
    if not parts:
        return json.dumps(evidence, default=str)[:200]
    return "; ".join(parts)


def _result_to_row(result: TestResult, columns: list[str]) -> dict[str, str]:
    mapping: dict[str, str] = {
        "case_id": result.case_id,
        "probe_id": result.probe_id,
        "input_text": result.input_text,
        "response_text": result.response_text,
        "passed": str(result.passed),
        "score": f"{result.score:.4f}",
        "severity": result.severity,
        "confidence": f"{result.confidence:.4f}",
        "evidence_summary": _evidence_summary(result.evidence),
        "remediation": "; ".join(result.remediation),
    }
    return {col: mapping.get(col, "") for col in columns}


class CsvReportWriter:

    def __init__(self, columns: list[str] | None = None) -> None:
        self._columns = columns or DEFAULT_COLUMNS

    def write(self, report: RunReport, path: str | Path) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)

        with out.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self._columns)
            writer.writeheader()
            for result in report.results:
                writer.writerow(_result_to_row(result, self._columns))

        return out.resolve()
