from __future__ import annotations

import json
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, ElementTree, indent

from aegisrt.core.result import RunReport, TestResult


class JunitReportWriter:

    def write(self, report: RunReport, path: str | Path) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)

        total = len(report.results)
        failures = sum(1 for r in report.results if not r.passed)

        suite = Element("testsuite")
        suite.set("name", f"aegisrt-{report.run_id}")
        suite.set("tests", str(total))
        suite.set("failures", str(failures))
        suite.set("timestamp", report.timestamp)

        for result in report.results:
            tc = SubElement(suite, "testcase")
            tc.set("classname", result.probe_id)
            tc.set("name", result.case_id)

            if not result.passed:
                fail_el = SubElement(tc, "failure")
                fail_el.set(
                    "message",
                    f"severity={result.severity} confidence={result.confidence:.2f} "
                    f"score={result.score:.2f}",
                )
                fail_el.text = self._failure_body(result)

        tree = ElementTree(suite)
        indent(tree, space="  ")
        tree.write(str(out), xml_declaration=True, encoding="unicode")
        return out.resolve()

    @staticmethod
    def _failure_body(result: TestResult) -> str:
        lines = [
            f"Probe: {result.probe_id}",
            f"Severity: {result.severity}",
            f"Confidence: {result.confidence:.2f}",
            f"Score: {result.score:.2f}",
        ]
        if result.evidence:
            lines.append(f"Evidence: {json.dumps(result.evidence, default=str)}")
        if result.remediation:
            lines.append("Remediation:")
            for step in result.remediation:
                lines.append(f"  - {step}")
        return "\n".join(lines)
