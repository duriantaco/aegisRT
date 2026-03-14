from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aegisrt.core.result import RunReport, TestResult


_SEVERITY_TO_SARIF_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


class SarifReportWriter:

    SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
    VERSION = "2.1.0"

    def write(self, report: RunReport, path: str | Path) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        sarif = self._build(report)
        out.write_text(json.dumps(sarif, indent=2, default=str), encoding="utf-8")
        return out.resolve()

    def _build(self, report: RunReport) -> dict[str, Any]:
        rules = self._collect_rules(report.results)
        return {
            "$schema": self.SCHEMA,
            "version": self.VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AegisRT",
                            "informationUri": "https://github.com/aegisrt/aegisrt",
                            "version": "0.1.0",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": [self._map_result(r) for r in report.results if not r.passed],
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "properties": {
                                "run_id": report.run_id,
                                "timestamp": report.timestamp,
                            },
                        }
                    ],
                }
            ],
        }

    @staticmethod
    def _collect_rules(results: list[TestResult]) -> dict[str, dict[str, Any]]:
        rules: dict[str, dict[str, Any]] = {}
        for r in results:
            if r.probe_id not in rules:
                rules[r.probe_id] = {
                    "id": r.probe_id,
                    "shortDescription": {"text": f"Security probe: {r.probe_id}"},
                    "defaultConfiguration": {
                        "level": _SEVERITY_TO_SARIF_LEVEL.get(r.severity.lower(), "warning")
                    },
                    "properties": {"severity": r.severity},
                }
        return rules

    @staticmethod
    def _map_result(result: TestResult) -> dict[str, Any]:
        return {
            "ruleId": result.probe_id,
            "level": _SEVERITY_TO_SARIF_LEVEL.get(result.severity.lower(), "warning"),
            "message": {
                "text": (
                    f"Probe {result.probe_id} detected a vulnerability "
                    f"(severity={result.severity}, confidence={result.confidence:.2f}, "
                    f"score={result.score:.2f})"
                )
            },
            "properties": {
                "case_id": result.case_id,
                "confidence": result.confidence,
                "score": result.score,
                "evidence": result.evidence,
                "remediation": result.remediation,
            },
        }
