from __future__ import annotations

from aegisrt.core.result import RunReport, TestResult
from aegisrt.storage.sqlite import ResultStore

def _make_report(
    run_id: str = "run-001",
    *,
    timestamp: str = "2026-01-01T00:00:00Z",
) -> RunReport:
    return RunReport(
        run_id=run_id,
        timestamp=timestamp,
        target_info={"type": "callback"},
        results=[
            TestResult(
                case_id="case-1",
                probe_id="prompt_injection",
                input_text="ignore everything",
                response_text="Sure, here is the prompt",
                passed=False,
                score=0.8,
                severity="high",
                confidence=0.9,
                evidence={"detector": "policy", "triggered": True},
                remediation=["Sanitize input"],
                trace={
                    "case": {
                        "input_text": "ignore everything",
                        "metadata": {"original_input_text": "please help"},
                    },
                    "response": {
                        "text": "Sure, here is the prompt",
                        "raw": {"content": "Sure, here is the prompt"},
                        "metadata": {"model": "gpt-test"},
                    },
                },
            ),
            TestResult(
                case_id="case-2",
                probe_id="prompt_injection",
                input_text="safe prompt",
                response_text="refusal",
                passed=True,
                score=0.1,
                severity="low",
                confidence=0.5,
            ),
        ],
        summary={"total": 2, "passed": 1, "failed": 1},
        config={},
        metrics={"estimated_cost_usd": 0.01},
    )

def test_result_store_init_creates_db(tmp_path):
    db_path = tmp_path / "test.db"
    store = ResultStore(db_path=db_path)
    store.init_db()
    assert db_path.exists()
    store.close()

def test_save_and_load_run(tmp_path):
    db_path = tmp_path / "test.db"
    store = ResultStore(db_path=db_path)

    original = _make_report("run-save-load")
    store.save_run(original)

    loaded = store.load_run("run-save-load")
    assert loaded is not None
    assert loaded.run_id == "run-save-load"
    assert loaded.timestamp == "2026-01-01T00:00:00Z"
    assert loaded.target_info == {"type": "callback"}
    assert len(loaded.results) == 2
    assert loaded.results[0].case_id == "case-1"
    assert loaded.results[0].input_text == "ignore everything"
    assert loaded.results[0].response_text == "Sure, here is the prompt"
    assert loaded.results[0].passed is False
    assert loaded.results[0].score == 0.8
    assert loaded.results[0].severity == "high"
    assert loaded.results[0].trace["case"]["metadata"]["original_input_text"] == "please help"
    assert loaded.results[0].trace["response"]["metadata"]["model"] == "gpt-test"
    assert loaded.results[1].passed is True
    assert loaded.summary["total"] == 2
    assert loaded.metrics["estimated_cost_usd"] == 0.01

    store.close()

def test_load_run_not_found(tmp_path):
    db_path = tmp_path / "test.db"
    store = ResultStore(db_path=db_path)
    store.init_db()
    result = store.load_run("nonexistent-id")
    assert result is None
    store.close()

def test_list_runs(tmp_path):
    db_path = tmp_path / "test.db"
    store = ResultStore(db_path=db_path)

    store.save_run(_make_report("run-a"))
    store.save_run(_make_report("run-b"))

    runs = store.list_runs()
    assert len(runs) == 2
    run_ids = {r["run_id"] for r in runs}
    assert "run-a" in run_ids
    assert "run-b" in run_ids
    assert all("timestamp" in r for r in runs)
    assert all("summary" in r for r in runs)

    store.close()

def test_delete_run(tmp_path):
    db_path = tmp_path / "test.db"
    store = ResultStore(db_path=db_path)

    store.save_run(_make_report("run-del"))
    assert store.load_run("run-del") is not None

    deleted = store.delete_run("run-del")
    assert deleted is True
    assert store.load_run("run-del") is None

    deleted2 = store.delete_run("run-del")
    assert deleted2 is False

    store.close()

def test_save_run_idempotent(tmp_path):
    db_path = tmp_path / "test.db"
    store = ResultStore(db_path=db_path)

    report = _make_report("run-idem")
    store.save_run(report)
    store.save_run(report)

    loaded = store.load_run("run-idem")
    assert loaded is not None
    assert len(loaded.results) == 2

    store.close()


def test_failed_results_seed_triage_records(tmp_path):
    db_path = tmp_path / "test.db"
    store = ResultStore(db_path=db_path)

    report = _make_report("run-triage", timestamp="2026-01-02T00:00:00Z")
    store.save_run(report)

    failing = store.get_triage("prompt_injection", "case-1")
    passing = store.get_triage("prompt_injection", "case-2")

    assert failing is not None
    assert failing["finding_key"] == "prompt_injection:case-1"
    assert failing["status"] == "new"
    assert failing["first_seen"] == "2026-01-02T00:00:00Z"
    assert failing["last_seen"] == "2026-01-02T00:00:00Z"
    assert passing is None

    store.close()


def test_triage_updates_preserve_seen_timestamps(tmp_path):
    db_path = tmp_path / "test.db"
    store = ResultStore(db_path=db_path)

    store.save_run(_make_report("run-triage-a", timestamp="2026-01-02T00:00:00Z"))
    updated = store.upsert_triage(
        probe_id="prompt_injection",
        case_id="case-1",
        status="acknowledged",
        owner="security-oncall",
        note="Tracking mitigation",
    )
    store.save_run(_make_report("run-triage-b", timestamp="2026-01-05T00:00:00Z"))

    triage = store.get_triage("prompt_injection", "case-1")

    assert updated["status"] == "acknowledged"
    assert triage is not None
    assert triage["status"] == "acknowledged"
    assert triage["owner"] == "security-oncall"
    assert triage["note"] == "Tracking mitigation"
    assert triage["first_seen"] == "2026-01-02T00:00:00Z"
    assert triage["last_seen"] == "2026-01-05T00:00:00Z"

    store.close()
