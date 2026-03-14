
from __future__ import annotations

import json
import csv
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aegisrt.config.models import (
    BenchmarkConfig,
    BenchmarkTargetConfig,
    ProbeConfig,
    RuntimeConfig,
)
from aegisrt.core.benchmark import BenchmarkReport, BenchmarkRunner, ModelScore
from aegisrt.core.result import RunReport, TestResult
from aegisrt.reports.benchmark_report import (
    BenchmarkCsvReportWriter,
    BenchmarkHtmlReportWriter,
    BenchmarkTerminalReporter,
)


def _make_results(probe_ids: list[str], pass_rate: float = 1.0) -> list[TestResult]:
    results = []
    for i, pid in enumerate(probe_ids):
        passed = (i / max(len(probe_ids), 1)) < pass_rate
        results.append(
            TestResult(
                case_id=f"case_{pid}_{i}",
                probe_id=pid,
                passed=passed,
                score=1.0 if passed else 0.0,
                severity="high",
                confidence=0.9,
            )
        )
    return results


def _make_run_report(
    run_id: str,
    probe_ids: list[str],
    pass_rate: float = 1.0,
) -> RunReport:
    results = _make_results(probe_ids, pass_rate)
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    return RunReport(
        run_id=run_id,
        timestamp="2026-03-11T00:00:00Z",
        results=results,
        summary={
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "pass_rate": round(passed / total, 4) if total else 1.0,
            "duration_seconds": 1.0,
        },
    )


def _make_benchmark_config(
    target_names: list[str],
    probe_ids: list[str] | None = None,
) -> BenchmarkConfig:
    targets = [
        BenchmarkTargetConfig(
            name=name,
            type="callback",
        )
        for name in target_names
    ]
    probes = [
        ProbeConfig(
            id=pid,
            family=pid,
            generator="static",
            detectors=["regex"],
        )
        for pid in (probe_ids or ["prompt_injection"])
    ]
    return BenchmarkConfig(
        targets=targets,
        probes=probes,
        runtime=RuntimeConfig(concurrency=1),
    )


class TestBenchmarkConfig:

    def test_basic_config(self):
        cfg = _make_benchmark_config(["model_a", "model_b"])
        assert len(cfg.targets) == 2
        assert cfg.targets[0].name == "model_a"
        assert cfg.targets[1].name == "model_b"

    def test_config_has_probes(self):
        cfg = _make_benchmark_config(["m"], ["p1", "p2"])
        assert len(cfg.probes) == 2

    def test_target_defaults(self):
        t = BenchmarkTargetConfig(name="test", type="http")
        assert t.timeout_seconds == 30
        assert t.retries == 1
        assert t.url is None

    def test_config_optional_fields(self):
        cfg = BenchmarkConfig(
            targets=[BenchmarkTargetConfig(name="x", type="callback")],
            probes=[ProbeConfig(id="p", family="f", generator="g", detectors=["d"])],
        )
        assert cfg.runtime is None
        assert cfg.providers is None
        assert cfg.report is None


class TestModelScore:

    def test_defaults(self):
        s = ModelScore(target_name="test")
        assert s.total == 0
        assert s.passed == 0
        assert s.pass_rate == 1.0
        assert s.by_category == {}

    def test_with_data(self):
        s = ModelScore(
            target_name="m1",
            total=100,
            passed=95,
            failed=5,
            pass_rate=0.95,
            by_category={
                "injection": {"total": 50, "passed": 48, "failed": 2, "pass_rate": 0.96},
            },
        )
        assert s.by_category["injection"]["pass_rate"] == 0.96


class TestBenchmarkReport:

    def test_defaults(self):
        r = BenchmarkReport(benchmark_id="abc", timestamp="2026-01-01")
        assert r.target_names == []
        assert r.categories == []
        assert r.scores == []

    def test_serialization(self):
        r = BenchmarkReport(
            benchmark_id="abc",
            timestamp="2026-01-01",
            target_names=["m1"],
            scores=[ModelScore(target_name="m1", total=10, passed=9, failed=1, pass_rate=0.9)],
        )
        data = json.loads(r.model_dump_json())
        assert data["benchmark_id"] == "abc"
        assert len(data["scores"]) == 1

    def test_roundtrip(self):
        r = BenchmarkReport(
            benchmark_id="test",
            timestamp="2026-01-01",
            target_names=["a", "b"],
            categories=["cat1"],
            scores=[
                ModelScore(target_name="a", total=5, passed=5, pass_rate=1.0),
                ModelScore(target_name="b", total=5, passed=3, failed=2, pass_rate=0.6),
            ],
            summary={"target_count": 2},
        )
        restored = BenchmarkReport.model_validate(json.loads(r.model_dump_json()))
        assert restored.benchmark_id == "test"
        assert len(restored.scores) == 2


def _make_mock_runner_cls(report: RunReport):

    class MockSecurityRunner:
        def __init__(self, config, *, callback_fn=None, run_id=None, no_cache=False):
            self.config = config
            self.callback_fn = callback_fn
            self.run_id = run_id

        def run(self) -> RunReport:
            return report

    return MockSecurityRunner


def _make_failing_runner_cls():

    class FailingRunner:
        def __init__(self, config, *, callback_fn=None, run_id=None, no_cache=False):
            pass

        def run(self) -> RunReport:
            raise RuntimeError("API down")

    return FailingRunner


class TestBenchmarkRunner:

    def test_basic_run(self):
        cfg = _make_benchmark_config(["model_a"], ["prompt_injection"])
        probes = ["prompt_injection"] * 5
        mock_cls = _make_mock_runner_cls(_make_run_report("r1", probes))

        runner = BenchmarkRunner(cfg)
        report = runner._run_with_runner_cls(mock_cls)

        assert isinstance(report, BenchmarkReport)
        assert len(report.target_names) == 1
        assert report.target_names[0] == "model_a"
        assert len(report.scores) == 1

    def test_multi_target(self):
        cfg = _make_benchmark_config(["model_a", "model_b"], ["p1", "p2"])
        probes = ["p1", "p1", "p2", "p2"]
        mock_cls = _make_mock_runner_cls(_make_run_report("r1", probes))

        runner = BenchmarkRunner(cfg)
        report = runner._run_with_runner_cls(mock_cls)

        assert len(report.target_names) == 2
        assert len(report.scores) == 2
        assert "model_a" in report.per_target_results
        assert "model_b" in report.per_target_results

    def test_target_failure_handled(self):
        cfg = _make_benchmark_config(["good", "bad"], ["p1"])

        call_count = [0]
        good_report = _make_run_report("r1", ["p1"])

        class MixedRunner:
            def __init__(self, config, *, callback_fn=None, run_id=None, no_cache=False):
                pass

            def run(self) -> RunReport:
                call_count[0] += 1
                if call_count[0] == 1:
                    return good_report
                raise RuntimeError("API down")

        runner = BenchmarkRunner(cfg)
        report = runner._run_with_runner_cls(MixedRunner)

        assert len(report.scores) == 2
        good_score = next(s for s in report.scores if s.target_name == "good")
        bad_score = next(s for s in report.scores if s.target_name == "bad")
        assert good_score.total > 0
        assert bad_score.total == 0

    def test_ranking(self):
        cfg = _make_benchmark_config(["best", "worst"], ["p1"])

        results_map = {
            "best": _make_run_report("r1", ["p1"] * 10, pass_rate=1.0),
            "worst": _make_run_report("r2", ["p1"] * 10, pass_rate=0.5),
        }

        class RankRunner:
            def __init__(self, config, *, callback_fn=None, run_id=None, no_cache=False):
                self._run_id = run_id or ""

            def run(self) -> RunReport:
                name = self._run_id.rsplit("_", 1)[-1]
                return results_map.get(name, results_map["best"])

        runner = BenchmarkRunner(cfg)
        report = runner._run_with_runner_cls(RankRunner)

        ranking = report.summary.get("ranking", [])
        assert len(ranking) == 2
        assert ranking[0]["target"] == "best"
        assert ranking[0]["rank"] == 1

    def test_matrix_populated(self):
        cfg = _make_benchmark_config(["m1"], ["p1", "p2"])
        mock_cls = _make_mock_runner_cls(
            _make_run_report("r1", ["p1", "p1", "p2", "p2"])
        )

        runner = BenchmarkRunner(cfg)
        report = runner._run_with_runner_cls(mock_cls)

        matrix = report.summary.get("matrix", {})
        assert "p1" in matrix or "p2" in matrix
        assert len(report.categories) >= 1

    def test_build_run_config(self):
        cfg = _make_benchmark_config(["m1"], ["p1"])
        runner = BenchmarkRunner(cfg)

        target_cfg = cfg.targets[0]
        run_config = runner._build_run_config(target_cfg)

        assert run_config.target.type == "callback"
        assert len(run_config.probes) == 1
        assert run_config.probes[0].id == "p1"

    def test_empty_targets(self):
        cfg = BenchmarkConfig(
            targets=[],
            probes=[ProbeConfig(id="p", family="f", generator="g", detectors=["d"])],
        )
        mock_cls = _make_mock_runner_cls(_make_run_report("r", []))

        runner = BenchmarkRunner(cfg)
        report = runner._run_with_runner_cls(mock_cls)

        assert report.target_names == []
        assert report.scores == []

    def test_callback_fn_passed(self):
        cfg = _make_benchmark_config(["m1"], ["p1"])
        cb = lambda prompt: "response"

        captured = {}

        class CapturingRunner:
            def __init__(self, config, *, callback_fn=None, run_id=None, no_cache=False):
                captured["callback_fn"] = callback_fn

            def run(self) -> RunReport:
                return _make_run_report("r1", ["p1"])

        runner = BenchmarkRunner(cfg, callback_fns={"m1": cb})
        runner._run_with_runner_cls(CapturingRunner)

        assert captured["callback_fn"] is cb


class TestComputeScore:

    def test_all_passed(self):
        results = [
            TestResult(case_id="c1", probe_id="p1", passed=True, score=1.0, severity="high", confidence=0.9),
            TestResult(case_id="c2", probe_id="p1", passed=True, score=1.0, severity="high", confidence=0.9),
        ]
        score = BenchmarkRunner._compute_score("model_a", results)
        assert score.total == 2
        assert score.passed == 2
        assert score.pass_rate == 1.0

    def test_mixed_results(self):
        results = [
            TestResult(case_id="c1", probe_id="p1", passed=True, score=1.0, severity="high", confidence=0.9),
            TestResult(case_id="c2", probe_id="p1", passed=False, score=0.0, severity="high", confidence=0.9),
            TestResult(case_id="c3", probe_id="p2", passed=False, score=0.0, severity="high", confidence=0.9),
        ]
        score = BenchmarkRunner._compute_score("m", results)
        assert score.total == 3
        assert score.passed == 1
        assert score.failed == 2
        assert 0.33 <= score.pass_rate <= 0.34

    def test_per_category_breakdown(self):
        results = [
            TestResult(case_id="c1", probe_id="p1", passed=True, score=1.0, severity="high", confidence=0.9),
            TestResult(case_id="c2", probe_id="p1", passed=False, score=0.0, severity="high", confidence=0.9),
            TestResult(case_id="c3", probe_id="p2", passed=True, score=1.0, severity="high", confidence=0.9),
        ]
        score = BenchmarkRunner._compute_score("m", results)
        assert "p1" in score.by_category
        assert "p2" in score.by_category
        assert score.by_category["p1"]["pass_rate"] == 0.5
        assert score.by_category["p2"]["pass_rate"] == 1.0

    def test_empty_results(self):
        score = BenchmarkRunner._compute_score("m", [])
        assert score.total == 0
        assert score.pass_rate == 1.0

    def test_ignores_skipped_results_in_pass_rate(self):
        results = [
            TestResult(case_id="c1", probe_id="p1", passed=True, score=1.0, severity="high", confidence=0.9),
            TestResult(
                case_id="c2",
                probe_id="p1",
                passed=True,
                score=1.0,
                severity="high",
                confidence=0.9,
                evidence={"skipped": "budget_exceeded"},
            ),
            TestResult(case_id="c3", probe_id="p1", passed=False, score=0.0, severity="high", confidence=0.9),
        ]

        score = BenchmarkRunner._compute_score("m", results)

        assert score.total == 3
        assert score.passed == 1
        assert score.failed == 1
        assert score.pass_rate == 0.5
        assert score.by_category["p1"]["skipped"] == 1


class TestBuildSummary:

    def test_ranking_order(self):
        scores = [
            ModelScore(target_name="low", total=10, passed=5, failed=5, pass_rate=0.5),
            ModelScore(target_name="high", total=10, passed=9, failed=1, pass_rate=0.9),
            ModelScore(target_name="mid", total=10, passed=7, failed=3, pass_rate=0.7),
        ]
        summary = BenchmarkRunner._build_summary(scores, ["cat"])
        ranking = summary["ranking"]
        assert ranking[0]["target"] == "high"
        assert ranking[1]["target"] == "mid"
        assert ranking[2]["target"] == "low"

    def test_best_target(self):
        scores = [
            ModelScore(target_name="a", pass_rate=0.8),
            ModelScore(target_name="b", pass_rate=0.95),
        ]
        summary = BenchmarkRunner._build_summary(scores, [])
        assert summary["best_target"] == "b"
        assert summary["best_pass_rate"] == 0.95

    def test_empty_scores(self):
        summary = BenchmarkRunner._build_summary([], [])
        assert summary["target_count"] == 0

    def test_matrix_structure(self):
        scores = [
            ModelScore(
                target_name="m1",
                by_category={"cat1": {"pass_rate": 0.9}, "cat2": {"pass_rate": 0.8}},
            ),
        ]
        summary = BenchmarkRunner._build_summary(scores, ["cat1", "cat2"])
        matrix = summary["matrix"]
        assert matrix["cat1"]["m1"] == 0.9
        assert matrix["cat2"]["m1"] == 0.8


class TestBenchmarkTerminalReporter:

    def test_reports_without_error(self):
        report = BenchmarkReport(
            benchmark_id="test",
            timestamp="2026-01-01",
            target_names=["a", "b"],
            categories=["cat1"],
            scores=[
                ModelScore(
                    target_name="a",
                    total=10,
                    passed=9,
                    failed=1,
                    pass_rate=0.9,
                    by_category={"cat1": {"total": 10, "passed": 9, "failed": 1, "pass_rate": 0.9}},
                ),
                ModelScore(
                    target_name="b",
                    total=10,
                    passed=7,
                    failed=3,
                    pass_rate=0.7,
                    by_category={"cat1": {"total": 10, "passed": 7, "failed": 3, "pass_rate": 0.7}},
                ),
            ],
            summary={
                "target_count": 2,
                "ranking": [
                    {"rank": 1, "target": "a", "pass_rate": 0.9},
                    {"rank": 2, "target": "b", "pass_rate": 0.7},
                ],
                "matrix": {"cat1": {"a": 0.9, "b": 0.7}},
                "best_target": "a",
                "best_pass_rate": 0.9,
            },
        )
        reporter = BenchmarkTerminalReporter()
        reporter.report(report)

    def test_empty_report(self):
        report = BenchmarkReport(benchmark_id="e", timestamp="2026-01-01")
        reporter = BenchmarkTerminalReporter()
        reporter.report(report)


class TestBenchmarkHtmlReport:

    def test_writes_html_file(self, tmp_path: Path):
        report = BenchmarkReport(
            benchmark_id="html_test",
            timestamp="2026-01-01",
            target_names=["m1"],
            categories=["cat1", "cat2", "cat3"],
            scores=[
                ModelScore(
                    target_name="m1",
                    total=30,
                    passed=28,
                    failed=2,
                    pass_rate=0.9333,
                    by_category={
                        "cat1": {"total": 10, "passed": 10, "failed": 0, "pass_rate": 1.0},
                        "cat2": {"total": 10, "passed": 9, "failed": 1, "pass_rate": 0.9},
                        "cat3": {"total": 10, "passed": 9, "failed": 1, "pass_rate": 0.9},
                    },
                ),
            ],
            summary={
                "target_count": 1,
                "ranking": [{"rank": 1, "target": "m1", "pass_rate": 0.9333}],
                "matrix": {
                    "cat1": {"m1": 1.0},
                    "cat2": {"m1": 0.9},
                    "cat3": {"m1": 0.9},
                },
            },
        )
        out = BenchmarkHtmlReportWriter().write(report, tmp_path / "bench.html")
        assert out.exists()
        content = out.read_text()
        assert "<!DOCTYPE html>" in content
        assert "radarChart" in content
        assert "html_test" in content
        assert "m1" in content

    def test_radar_chart_data(self, tmp_path: Path):
        report = BenchmarkReport(
            benchmark_id="radar",
            timestamp="2026-01-01",
            target_names=["a", "b"],
            categories=["c1", "c2", "c3"],
            scores=[
                ModelScore(
                    target_name="a",
                    by_category={
                        "c1": {"pass_rate": 0.9},
                        "c2": {"pass_rate": 0.8},
                        "c3": {"pass_rate": 0.7},
                    },
                ),
                ModelScore(
                    target_name="b",
                    by_category={
                        "c1": {"pass_rate": 0.6},
                        "c2": {"pass_rate": 0.5},
                        "c3": {"pass_rate": 0.4},
                    },
                ),
            ],
            summary={"matrix": {}},
        )
        out = BenchmarkHtmlReportWriter().write(report, tmp_path / "radar.html")
        content = out.read_text()
        assert '"name": "a"' in content
        assert '"name": "b"' in content


class TestBenchmarkCsvReport:

    def test_writes_csv_file(self, tmp_path: Path):
        report = BenchmarkReport(
            benchmark_id="csv_test",
            timestamp="2026-01-01",
            target_names=["m1", "m2"],
            categories=["cat1", "cat2"],
            scores=[
                ModelScore(target_name="m1", pass_rate=0.95),
                ModelScore(target_name="m2", pass_rate=0.80),
            ],
            summary={
                "matrix": {
                    "cat1": {"m1": 0.97, "m2": 0.85},
                    "cat2": {"m1": 0.93, "m2": 0.75},
                },
            },
        )
        out = BenchmarkCsvReportWriter().write(report, tmp_path / "bench.csv")
        assert out.exists()

        with out.open() as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 3
        assert rows[0]["category"] == "cat1"
        assert rows[0]["m1"] == "97.0%"
        assert rows[2]["category"] == "OVERALL"
        assert rows[2]["m1"] == "95.0%"

    def test_csv_handles_missing_data(self, tmp_path: Path):
        report = BenchmarkReport(
            benchmark_id="missing",
            timestamp="2026-01-01",
            target_names=["m1"],
            categories=["cat1"],
            scores=[ModelScore(target_name="m1", pass_rate=0.5)],
            summary={"matrix": {"cat1": {}}},
        )
        out = BenchmarkCsvReportWriter().write(report, tmp_path / "miss.csv")
        content = out.read_text()
        assert "N/A" in content


class TestBenchmarkConfigLoader:

    def test_load_benchmark_config(self, tmp_path: Path):
        from aegisrt.config.loader import load_benchmark_config

        cfg_data = {
            "targets": [
                {"name": "model_a", "type": "http", "url": "http://localhost:8000/v1"},
                {"name": "model_b", "type": "openai_compat", "url": "http://localhost:8001/v1"},
            ],
            "probes": [
                {"id": "p1", "family": "f1", "generator": "static", "detectors": ["regex"]},
            ],
        }
        import yaml
        cfg_path = tmp_path / "bench.yaml"
        cfg_path.write_text(yaml.dump(cfg_data))

        cfg = load_benchmark_config(cfg_path)
        assert isinstance(cfg, BenchmarkConfig)
        assert len(cfg.targets) == 2
        assert cfg.targets[0].name == "model_a"

    def test_load_missing_file(self):
        from aegisrt.config.loader import load_benchmark_config

        with pytest.raises(FileNotFoundError):
            load_benchmark_config("/nonexistent/path.yaml")
