from __future__ import annotations

from aegisrt.core.comparison import run_comparison
from aegisrt.core.diff import compare_runs
from aegisrt.core.result import RunReport, TestResult
from aegisrt.config.models import ProbeConfig, RunConfig, TargetConfig


def _result(
    *,
    case_id: str,
    probe_id: str = "p1",
    passed: bool,
    skipped: bool = False,
) -> TestResult:
    evidence = {"skipped": "budget_exceeded"} if skipped else {}
    return TestResult(
        case_id=case_id,
        probe_id=probe_id,
        input_text="prompt",
        response_text="response",
        passed=passed,
        score=0.0 if passed else 0.9,
        severity="high",
        confidence=0.9,
        evidence=evidence,
    )


def _report(run_id: str, results: list[TestResult]) -> RunReport:
    return RunReport(
        run_id=run_id,
        timestamp="2026-03-12T00:00:00Z",
        results=results,
        summary={},
    )


def test_compare_runs_tracks_skipped_without_counting_them_as_improvements():
    base = _report("base", [_result(case_id="c1", passed=False)])
    compare = _report("compare", [_result(case_id="c1", passed=True, skipped=True)])

    diff = compare_runs(base, compare)

    assert diff.regressions == 0
    assert diff.improvements == 0
    assert len(diff.skipped) == 1
    assert diff.summary["compare_skipped"] == 1
    assert diff.summary["compare_passed"] == 0
    assert diff.summary["compare_failed"] == 0


def test_compare_runs_separates_persistent_passes_from_new_passes():
    base = _report(
        "base",
        [
            _result(case_id="same-pass", passed=True),
            _result(case_id="new-pass-later", passed=False),
        ],
    )
    compare = _report(
        "compare",
        [
            _result(case_id="same-pass", passed=True),
            _result(case_id="new-pass-later", passed=True),
        ],
    )

    diff = compare_runs(base, compare)

    assert len(diff.persistent_passes) == 1
    assert diff.persistent_passes[0].case_id == "same-pass"
    assert len(diff.new_passes) == 0
    assert len(diff.resolved) == 1


def test_run_comparison_summary_ignores_skipped_results(monkeypatch):
    skipped_report = _report(
        "run-1",
        [
            _result(case_id="c1", passed=True),
            _result(case_id="c2", passed=True, skipped=True),
            _result(case_id="c3", passed=False),
        ],
    )

    class StubRunner:
        def __init__(self, config, *, callback_fn=None, run_id=None, no_cache=False):
            self.config = config

        def run(self) -> RunReport:
            return skipped_report

    monkeypatch.setattr("aegisrt.core.runner.SecurityRunner", StubRunner)

    comparison = run_comparison(
        [
            RunConfig(
                target=TargetConfig(type="callback"),
                probes=[ProbeConfig(id="p1", family="p1", generator="static", detectors=["regex"])],
            )
        ]
    )

    summary = comparison.summary["per_target"]["target_0_callback"]
    assert summary["passed"] == 1
    assert summary["failed"] == 1
    assert summary["skipped"] == 1
    assert summary["pass_rate"] == 0.5
