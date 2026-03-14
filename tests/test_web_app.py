from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

import aegisrt.web.app as web_app
from aegisrt.core.result import RunReport, TestResult
from aegisrt.storage.sqlite import ResultStore


def _result(
    *,
    case_id: str,
    probe_id: str = "prompt_injection",
    passed: bool,
    skipped: bool = False,
    severity: str = "high",
    score: float | None = None,
) -> TestResult:
    return TestResult(
        case_id=case_id,
        probe_id=probe_id,
        input_text=f"input-{case_id}",
        response_text=f"response-{case_id}",
        passed=passed,
        score=score if score is not None else (0.1 if passed else 0.9),
        severity=severity,
        confidence=0.9,
        evidence={"skipped": "budget_exceeded"} if skipped else {},
    )


def _report(
    run_id: str,
    results: list[TestResult],
    *,
    metrics: dict | None = None,
    summary: dict | None = None,
    config: dict | None = None,
    target_info: dict | None = None,
    timestamp: str = "2026-03-12T00:00:00Z",
) -> RunReport:
    return RunReport(
        run_id=run_id,
        timestamp=timestamp,
        target_info=target_info or {"type": "callback"},
        results=results,
        summary=summary or {},
        config=config or {"target": {"type": "callback"}},
        metrics=metrics or {},
    )


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "results.db"
    monkeypatch.setattr(web_app, "_get_store", lambda: ResultStore(db_path=db_path))
    return TestClient(web_app.app), db_path


def _store(db_path):
    return ResultStore(db_path=db_path)


def _seed_run(db_path, run_id="run-1", **kwargs):
    store = _store(db_path)
    results = kwargs.pop("results", [_result(case_id="c1", passed=False)])
    store.save_run(_report(run_id, results, **kwargs))
    store.close()


class TestHealth:
    def test_health_returns_ok(self, client):
        tc, _ = client
        resp = tc.get("/api/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert "version" in body
        assert "timestamp" in body


class TestListRuns:
    def test_empty_db(self, client):
        tc, _ = client
        resp = tc.get("/api/runs")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_returns_enriched_summaries(self, client):
        tc, db_path = client
        _seed_run(
            db_path,
            "run-a",
            summary={"total": 5, "passed": 3, "failed": 2, "pass_rate": 0.6},
        )
        _seed_run(
            db_path,
            "run-b",
            summary={"total": 1, "passed": 1, "failed": 0, "pass_rate": 1.0},
            timestamp="2026-03-13T00:00:00Z",
        )
        resp = tc.get("/api/runs")
        assert resp.status_code == 200
        runs = resp.json()
        assert len(runs) == 2
        assert runs[0]["run_id"] == "run-b"
        for run in runs:
            assert "total" in run
            assert "passed" in run
            assert "failed" in run
            assert "summary" in run


class TestGetRun:
    def test_returns_full_report(self, client):
        tc, db_path = client
        _seed_run(
            db_path,
            "run-detail",
            summary={"total": 1, "passed": 0, "failed": 1},
            metrics={"total_calls": 1, "avg_latency_ms": 100.0},
        )
        resp = tc.get("/api/runs/run-detail")
        assert resp.status_code == 200
        body = resp.json()
        assert body["run_id"] == "run-detail"
        assert "results" in body
        assert "config" in body
        assert "target_info" in body
        assert "summary" in body
        assert "metrics" in body
        assert "attack_sessions" in body

    def test_results_include_triage_metadata(self, client):
        tc, db_path = client
        _seed_run(
            db_path,
            "run-triage-detail",
            results=[
                _result(case_id="c1", passed=False),
                _result(case_id="c2", passed=True),
            ],
        )

        resp = tc.get("/api/runs/run-triage-detail")
        assert resp.status_code == 200
        results = resp.json()["results"]
        assert results[0]["finding_key"] == "prompt_injection:c1"
        assert results[0]["triage"]["status"] == "new"
        assert results[1]["triage"] is None

    def test_run_detail_includes_attack_session_summary(self, client):
        tc, db_path = client
        store = _store(db_path)
        store.save_run(
            _report(
                "run-session-detail",
                [
                    TestResult(
                        case_id="c1",
                        probe_id="prompt_injection",
                        input_text="input-c1",
                        response_text="response-c1",
                        passed=False,
                        score=0.9,
                        severity="critical",
                        confidence=0.9,
                        trace={
                            "session_id": "sess-1",
                            "attack_id": "attack-1",
                            "steps": [
                                {"agent_id": "planner", "agent_role": "planner", "content": "plan"},
                                {
                                    "agent_id": "tool",
                                    "type": "tool_call",
                                    "tool_name": "memory_lookup",
                                    "trust_boundary": "memory_store",
                                },
                            ],
                        },
                    )
                ],
            )
        )
        store.close()

        resp = tc.get("/api/runs/run-session-detail")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["attack_sessions"]) == 1
        session = body["attack_sessions"][0]
        assert session["session_id"] == "sess-1"
        assert session["finding_count"] == 1
        assert session["step_count"] == 2
        assert session["tool_names"] == ["memory_lookup"]
        assert session["trust_boundaries"] == ["memory_store"]

    def test_404_for_missing_run(self, client):
        tc, _ = client
        resp = tc.get("/api/runs/nonexistent")
        assert resp.status_code == 404

    def test_metrics_payload_preserved(self, client):
        """Regression: metrics must stay in run detail."""
        tc, db_path = client
        store = _store(db_path)
        store.save_run(
            _report(
                "run-metrics",
                [_result(case_id="c1", passed=False)],
                summary={"total": 1, "passed": 0, "failed": 1, "pass_rate": 0.0},
                metrics={
                    "total_calls": 1,
                    "avg_latency_ms": 123.4,
                    "total_tokens": 321,
                    "budget": {"max_usd": 5.0, "spent_usd": 0.42},
                },
            )
        )
        store.close()

        resp = tc.get("/api/runs/run-metrics")
        assert resp.status_code == 200
        payload = resp.json()
        assert payload["run_id"] == "run-metrics"
        assert payload["metrics"]["total_calls"] == 1
        assert payload["metrics"]["avg_latency_ms"] == 123.4
        assert payload["metrics"]["budget"]["spent_usd"] == 0.42


class TestDeleteRun:
    def test_delete_existing_run(self, client):
        tc, db_path = client
        _seed_run(db_path, "to-delete")
        resp = tc.delete("/api/runs/to-delete")
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True
        assert tc.get("/api/runs/to-delete").status_code == 404

    def test_delete_missing_run_returns_404(self, client):
        tc, _ = client
        resp = tc.delete("/api/runs/ghost")
        assert resp.status_code == 404


class TestTriage:
    def test_update_triage_persists_to_run_payload(self, client):
        tc, db_path = client
        _seed_run(db_path, "triage-run", results=[_result(case_id="c1", passed=False)])

        update = tc.put(
            "/api/triage",
            json={
                "probe_id": "prompt_injection",
                "case_id": "c1",
                "status": "acknowledged",
                "owner": "security-oncall",
                "note": "Repro confirmed",
            },
        )
        assert update.status_code == 200
        triage = update.json()
        assert triage["finding_key"] == "prompt_injection:c1"
        assert triage["status"] == "acknowledged"
        assert triage["owner"] == "security-oncall"
        assert triage["note"] == "Repro confirmed"

        resp = tc.get("/api/runs/triage-run")
        assert resp.status_code == 200
        result = resp.json()["results"][0]
        assert result["triage"]["status"] == "acknowledged"
        assert result["triage"]["owner"] == "security-oncall"
        assert result["triage"]["note"] == "Repro confirmed"

    def test_rejects_invalid_triage_status(self, client):
        tc, _ = client
        resp = tc.put(
            "/api/triage",
            json={
                "probe_id": "prompt_injection",
                "case_id": "c1",
                "status": "closed",
            },
        )
        assert resp.status_code == 400
        assert "Unsupported triage status" in resp.json()["detail"]


class TestStartRun:
    def test_start_run_returns_run_id(self, client):
        tc, _ = client
        resp = tc.post("/api/runs", json={"config_path": None})
        assert resp.status_code == 200
        body = resp.json()
        assert "run_id" in body
        assert body["status"] == "started"


class TestResultsFiltering:
    @pytest.fixture(autouse=True)
    def _seed(self, client):
        tc, db_path = client
        self.tc = tc
        store = _store(db_path)
        store.save_run(
            _report(
                "filter-run",
                [
                    _result(case_id="c1", probe_id="injection", passed=True, severity="high"),
                    _result(case_id="c2", probe_id="injection", passed=False, severity="high"),
                    _result(case_id="c3", probe_id="leakage", passed=False, severity="critical"),
                    _result(case_id="c4", probe_id="leakage", passed=True, severity="medium"),
                ],
            )
        )
        store.close()

    def test_no_filter_returns_all(self):
        resp = self.tc.get("/api/runs/filter-run/results")
        assert resp.status_code == 200
        assert len(resp.json()) == 4

    def test_filter_by_severity(self):
        resp = self.tc.get("/api/runs/filter-run/results?severity=critical")
        assert resp.status_code == 200
        results = resp.json()
        assert len(results) == 1
        assert results[0]["probe_id"] == "leakage"
        assert results[0]["severity"] == "critical"

    def test_filter_by_passed(self):
        resp = self.tc.get("/api/runs/filter-run/results?passed=false")
        assert resp.status_code == 200
        results = resp.json()
        assert len(results) == 2
        assert all(not r["passed"] for r in results)

    def test_filter_by_probe_id(self):
        resp = self.tc.get("/api/runs/filter-run/results?probe_id=injection")
        assert resp.status_code == 200
        results = resp.json()
        assert len(results) == 2
        assert all(r["probe_id"] == "injection" for r in results)

    def test_combined_filters(self):
        resp = self.tc.get(
            "/api/runs/filter-run/results?probe_id=injection&passed=false"
        )
        assert resp.status_code == 200
        results = resp.json()
        assert len(results) == 1
        assert results[0]["case_id"] == "c2"

    def test_filter_missing_run_404(self):
        resp = self.tc.get("/api/runs/nope/results?severity=high")
        assert resp.status_code == 404


class TestDiffRuns:
    def test_full_backend_comparison(self, client):
        tc, db_path = client
        store = _store(db_path)
        store.save_run(
            _report(
                "base-run",
                [
                    _result(case_id="persistent", passed=False),
                    _result(case_id="resolved", passed=False),
                    _result(case_id="regression", passed=True),
                ],
            )
        )
        store.save_run(
            _report(
                "compare-run",
                [
                    _result(case_id="persistent", passed=False),
                    _result(case_id="resolved", passed=True),
                    _result(case_id="regression", passed=False),
                    _result(case_id="new-pass", passed=True),
                    _result(case_id="skipped", passed=True, skipped=True),
                ],
            )
        )
        store.close()

        resp = tc.get("/api/runs/base-run/diff/compare-run")
        assert resp.status_code == 200
        payload = resp.json()
        assert payload["base_run_id"] == "base-run"
        assert payload["compare_run_id"] == "compare-run"
        assert payload["regressions"] == 1
        assert payload["improvements"] == 1
        assert len(payload["new_failures"]) == 1
        assert len(payload["resolved"]) == 1
        assert len(payload["persistent_failures"]) == 1
        assert len(payload["persistent_passes"]) == 0
        assert len(payload["new_passes"]) == 1
        assert len(payload["skipped"]) == 1
        assert payload["summary"]["compare_skipped"] == 1

    def test_identical_runs(self, client):
        tc, db_path = client
        store = _store(db_path)
        results = [
            _result(case_id="a", passed=True),
            _result(case_id="b", passed=False),
        ]
        store.save_run(_report("same-a", results))
        store.save_run(_report("same-b", results))
        store.close()

        resp = tc.get("/api/runs/same-a/diff/same-b")
        assert resp.status_code == 200
        payload = resp.json()
        assert payload["regressions"] == 0
        assert payload["improvements"] == 0
        assert len(payload["new_failures"]) == 0
        assert len(payload["resolved"]) == 0
        assert len(payload["persistent_failures"]) == 1
        assert len(payload["persistent_passes"]) == 1
        assert len(payload["new_passes"]) == 0

    def test_empty_runs(self, client):
        tc, db_path = client
        store = _store(db_path)
        store.save_run(_report("empty-a", []))
        store.save_run(_report("empty-b", []))
        store.close()

        resp = tc.get("/api/runs/empty-a/diff/empty-b")
        assert resp.status_code == 200
        payload = resp.json()
        assert payload["regressions"] == 0
        assert payload["improvements"] == 0

    def test_diff_missing_base_404(self, client):
        tc, db_path = client
        _seed_run(db_path, "exists")
        resp = tc.get("/api/runs/nope/diff/exists")
        assert resp.status_code == 404

    def test_diff_missing_compare_404(self, client):
        tc, db_path = client
        _seed_run(db_path, "exists")
        resp = tc.get("/api/runs/exists/diff/nope")
        assert resp.status_code == 404


class TestHistory:
    def test_empty_history(self, client):
        tc, _ = client
        resp = tc.get("/api/history")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_trend_indicators(self, client):
        tc, db_path = client
        store = _store(db_path)
        store.save_run(
            _report(
                "h1", [],
                summary={"total": 10, "passed": 5, "failed": 5, "pass_rate": 0.5},
                timestamp="2026-03-01T00:00:00Z",
            )
        )
        store.save_run(
            _report(
                "h2", [],
                summary={"total": 10, "passed": 8, "failed": 2, "pass_rate": 0.8},
                timestamp="2026-03-02T00:00:00Z",
            )
        )
        store.save_run(
            _report(
                "h3", [],
                summary={"total": 10, "passed": 8, "failed": 2, "pass_rate": 0.8},
                timestamp="2026-03-03T00:00:00Z",
            )
        )
        store.save_run(
            _report(
                "h4", [],
                summary={"total": 10, "passed": 6, "failed": 4, "pass_rate": 0.6},
                timestamp="2026-03-04T00:00:00Z",
            )
        )
        store.close()

        resp = tc.get("/api/history")
        assert resp.status_code == 200
        history = resp.json()
        assert len(history) == 4

        trends = {h["run_id"]: h["trend"] for h in history}
        assert trends["h1"] == "baseline"
        assert trends["h2"] == "up"
        assert trends["h3"] == "same"
        assert trends["h4"] == "down"

        for entry in history:
            assert "run_id" in entry
            assert "timestamp" in entry
            assert "total" in entry
            assert "passed" in entry
            assert "failed" in entry
            assert "pass_rate" in entry
            assert "trend" in entry


class TestReportExport:
    @pytest.fixture(autouse=True)
    def _seed(self, client):
        tc, db_path = client
        self.tc = tc
        _seed_run(
            db_path,
            "export-run",
            summary={"total": 1, "passed": 0, "failed": 1},
        )

    def test_json_export(self):
        resp = self.tc.get("/api/runs/export-run/report/json")
        assert resp.status_code == 200
        body = resp.json()
        assert "run_id" in body

    def test_html_export(self):
        resp = self.tc.get("/api/runs/export-run/report/html")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "<html" in resp.text.lower() or "<!doctype" in resp.text.lower()

    def test_sarif_export(self):
        resp = self.tc.get("/api/runs/export-run/report/sarif")
        assert resp.status_code == 200
        body = resp.json()
        assert "$schema" in body or "version" in body

    def test_junit_export(self):
        resp = self.tc.get("/api/runs/export-run/report/junit")
        assert resp.status_code == 200
        assert "xml" in resp.headers["content-type"]
        assert "<?xml" in resp.text or "<testsuite" in resp.text

    def test_unsupported_format_400(self):
        resp = self.tc.get("/api/runs/export-run/report/csv")
        assert resp.status_code == 400

    def test_export_missing_run_404(self):
        resp = self.tc.get("/api/runs/nope/report/json")
        assert resp.status_code == 404


class TestProbes:
    def test_probes_returns_list(self, client):
        tc, _ = client
        resp = tc.get("/api/probes")
        assert resp.status_code == 200
        probes = resp.json()
        assert isinstance(probes, list)
        assert len(probes) > 0
        for p in probes:
            assert "id" in p
            assert "family" in p
            assert "severity" in p
            assert "description" in p
            assert "seed_count" in p
            assert isinstance(p["seed_count"], int)


class TestSuites:
    def test_suites_returns_list(self, client):
        tc, _ = client
        resp = tc.get("/api/suites")
        assert resp.status_code == 200
        suites = resp.json()
        assert isinstance(suites, list)
        assert len(suites) > 0
        for s in suites:
            assert "name" in s
            assert "description" in s
            assert "probe_count" in s
            assert "probes" in s
            assert isinstance(s["probes"], list)


class TestSPAServing:
    def test_root_serves_index(self, client):
        tc, _ = client
        resp = tc.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_favicon(self, client):
        tc, _ = client
        resp = tc.get("/favicon.svg")
        assert resp.status_code == 200
        assert "svg" in resp.headers["content-type"]

    def test_catch_all_returns_index(self, client):
        tc, _ = client
        resp = tc.get("/some/unknown/path")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
