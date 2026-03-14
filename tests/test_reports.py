from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from aegisrt.reports.json_report import JsonReportWriter
from aegisrt.reports.terminal import TerminalReporter
from aegisrt.reports.html_report import HtmlReportWriter
from aegisrt.reports.sarif_report import SarifReportWriter
from aegisrt.reports.junit_report import JunitReportWriter

def test_json_report_writes_valid_json(sample_run_report, tmp_output_dir):
    writer = JsonReportWriter()
    path = writer.write(sample_run_report, tmp_output_dir / "report.json")
    assert path.exists()

    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["run_id"] == "testreport01"
    assert isinstance(data["results"], list)
    assert len(data["results"]) == 1
    assert data["results"][0]["probe_id"] == "prompt_injection"

def test_terminal_reporter_runs_without_error(sample_run_report):
    from rich.console import Console
    import io

    buf = io.StringIO()
    console = Console(file=buf, force_terminal=True, width=120)
    reporter = TerminalReporter(console=console)
    reporter.report(sample_run_report, duration_seconds=1.5)

    output = buf.getvalue()
    assert "AegisRT" in output
    assert len(output) > 0

def test_html_report_generates_html(sample_run_report, tmp_output_dir):
    writer = HtmlReportWriter()
    path = writer.write(sample_run_report, tmp_output_dir / "report.html")
    assert path.exists()

    html = path.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html
    assert "<html" in html
    assert "AegisRT" in html
    assert "testreport01" in html
    assert "</html>" in html

def test_sarif_report_valid_structure(sample_run_report, tmp_output_dir):
    writer = SarifReportWriter()
    path = writer.write(sample_run_report, tmp_output_dir / "report.sarif")
    assert path.exists()

    data = json.loads(path.read_text(encoding="utf-8"))
    assert "$schema" in data
    assert data["version"] == "2.1.0"
    assert "runs" in data
    assert len(data["runs"]) == 1

    run = data["runs"][0]
    assert "tool" in run
    assert run["tool"]["driver"]["name"] == "AegisRT"
    assert "results" in run
    assert "invocations" in run

def test_sarif_report_maps_failed_results(sample_run_report, tmp_output_dir):
    writer = SarifReportWriter()
    path = writer.write(sample_run_report, tmp_output_dir / "report.sarif")
    data = json.loads(path.read_text(encoding="utf-8"))
    sarif_results = data["runs"][0]["results"]
    assert len(sarif_results) == 1
    assert sarif_results[0]["ruleId"] == "prompt_injection"

def test_junit_report_valid_xml(sample_run_report, tmp_output_dir):
    writer = JunitReportWriter()
    path = writer.write(sample_run_report, tmp_output_dir / "report.xml")
    assert path.exists()

    tree = ET.parse(str(path))
    root = tree.getroot()
    assert root.tag == "testsuite"
    assert root.attrib["tests"] == "1"
    assert root.attrib["failures"] == "1"

    testcases = root.findall("testcase")
    assert len(testcases) == 1
    assert testcases[0].attrib["classname"] == "prompt_injection"

    failures = testcases[0].findall("failure")
    assert len(failures) == 1
