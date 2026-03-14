
from __future__ import annotations

import asyncio
import tempfile
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from aegisrt.core.batch_runner import (
    BatchRunner,
    _CheckpointStore,
    _TokenBucket,
)
from aegisrt.core.cost_guard import BudgetExceededError, CostGuard
from aegisrt.core.metrics import estimate_cost
from aegisrt.core.result import Detection, TestCase, TestResult
from aegisrt.detectors.base import BaseDetector
from aegisrt.targets.base import BaseTarget, TargetResponse


class StubTarget(BaseTarget):

    def __init__(
        self,
        response_text: str = "I cannot help with that.",
        prompt_tokens: int = 10,
        completion_tokens: int = 20,
    ) -> None:
        self._response_text = response_text
        self._prompt_tokens = prompt_tokens
        self._completion_tokens = completion_tokens
        self.call_count = 0

    def execute(self, prompt: str) -> TargetResponse:
        self.call_count += 1
        return TargetResponse(
            text=self._response_text,
            latency_ms=5.0,
            prompt_tokens=self._prompt_tokens,
            completion_tokens=self._completion_tokens,
            total_tokens=self._prompt_tokens + self._completion_tokens,
        )


class FailingTarget(BaseTarget):

    def execute(self, prompt: str) -> TargetResponse:
        raise RuntimeError("target exploded")


class StubDetector(BaseDetector):

    id: str = "stub_detector"

    def __init__(self, triggered: bool = False, score: float = 0.0):
        self.id = "stub_detector"
        self._triggered = triggered
        self._score = score

    def check(self, case: TestCase, response: TargetResponse) -> Detection:
        return Detection(
            detector=self.id,
            triggered=self._triggered,
            score=self._score,
            evidence={},
        )


def _make_cases(n: int, probe_id: str = "test_probe") -> list[TestCase]:
    return [
        TestCase(id=f"case_{i:04d}", probe_id=probe_id, input_text=f"prompt {i}")
        for i in range(n)
    ]


class TestCostGuard:

    def test_no_budget_no_enforcement(self):
        guard = CostGuard(max_usd=0.0)
        assert not guard.enabled
        assert guard.remaining == float("inf")
        guard.record(1000, 1000, "gpt-4o")

    def test_budget_tracking(self):
        guard = CostGuard(max_usd=10.0, model="gpt-4o-mini")
        guard.record(1000, 500, "gpt-4o-mini")
        assert guard.total_spent > 0
        assert guard.remaining < 10.0
        assert guard.total_calls == 1
        tokens_in, tokens_out = guard.total_tokens
        assert tokens_in == 1000
        assert tokens_out == 500

    def test_budget_exceeded_raises(self):
        guard = CostGuard(max_usd=0.001, model="gpt-4o")
        with pytest.raises(BudgetExceededError) as exc_info:
            guard.record(1000, 1000, "gpt-4o")
        assert exc_info.value.spent > 0
        assert exc_info.value.limit == 0.001

    def test_check_without_recording(self):
        guard = CostGuard(max_usd=0.001)
        guard._total_spent = 0.002
        with pytest.raises(BudgetExceededError):
            guard.check()

    def test_utilization(self):
        guard = CostGuard(max_usd=1.0)
        assert guard.utilization == 0.0
        guard._total_spent = 0.5
        assert guard.utilization == 0.5
        guard._total_spent = 2.0
        assert guard.utilization == 1.0

    def test_summary(self):
        guard = CostGuard(max_usd=5.0)
        guard.record(100, 50, "gpt-4o-mini")
        summary = guard.summary()
        assert summary["max_usd"] == 5.0
        assert summary["total_calls"] == 1
        assert summary["total_tokens_in"] == 100
        assert summary["total_tokens_out"] == 50
        assert "remaining_usd" in summary
        assert "utilization_pct" in summary

    def test_thread_safety(self):
        guard = CostGuard(max_usd=100.0, model="gpt-4o-mini")
        errors: list[Exception] = []

        def worker():
            try:
                for _ in range(100):
                    guard.record(10, 10, "gpt-4o-mini")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert guard.total_calls == 1000

    def test_warning_logged(self, caplog):
        guard = CostGuard(max_usd=0.01, warn_at_pct=0.5, model="gpt-4o")
        try:
            guard.record(1000, 1000, "gpt-4o")
        except BudgetExceededError:
            pass
        assert guard._warned


class TestTokenBucket:

    def test_disabled_when_zero(self):
        bucket = _TokenBucket(rate_per_minute=0)
        assert bucket._disabled
        asyncio.run(bucket.acquire())

    def test_allows_burst_up_to_capacity(self):
        bucket = _TokenBucket(rate_per_minute=100)
        async def burst():
            for _ in range(100):
                await bucket.acquire()
        asyncio.run(burst())

    def test_negative_rate_disabled(self):
        bucket = _TokenBucket(rate_per_minute=-1)
        assert bucket._disabled


class TestCheckpointStore:

    def test_save_and_load(self, tmp_path):
        cp = _CheckpointStore(tmp_path / "cp.db")
        case = TestCase(id="c1", probe_id="p1", input_text="test")
        response = TargetResponse(text="response", latency_ms=10.0)
        result = TestResult(
            case_id="c1",
            probe_id="p1",
            passed=True,
            score=0.0,
            severity="low",
            confidence=0.9,
        )

        cp.save_result(case, response, result)
        cp.flush()

        ids = cp.get_completed_ids()
        assert "c1" in ids

        results = cp.load_results()
        assert len(results) == 1
        assert results[0].case_id == "c1"
        assert results[0].passed is True

        cp.close()

    def test_meta(self, tmp_path):
        cp = _CheckpointStore(tmp_path / "cp.db")
        assert cp.get_meta("run_id") is None
        cp.set_meta("run_id", "abc123")
        assert cp.get_meta("run_id") == "abc123"
        cp.close()

    def test_idempotent_save(self, tmp_path):
        cp = _CheckpointStore(tmp_path / "cp.db")
        case = TestCase(id="c1", probe_id="p1", input_text="test")
        response = TargetResponse(text="r", latency_ms=1.0)
        result = TestResult(
            case_id="c1", probe_id="p1", passed=True,
            score=0.0, severity="low", confidence=0.9,
        )
        cp.save_result(case, response, result)
        cp.save_result(case, response, result)
        cp.flush()
        assert len(cp.get_completed_ids()) == 1
        cp.close()


class TestBatchRunner:

    def test_run_batch_basic(self):
        target = StubTarget()
        detector = StubDetector()

        runner = BatchRunner(
            target=target,
            detectors=[detector],
            concurrency=4,
        )

        cases = _make_cases(10)
        results = runner.run_batch(cases)

        assert len(results) == 10
        assert all(isinstance(r, TestResult) for r in results)
        assert target.call_count == 10
        assert runner.completed_count == 10
        runner.close()

    def test_run_batch_preserves_order(self):
        target = StubTarget()
        runner = BatchRunner(
            target=target,
            detectors=[StubDetector()],
            concurrency=2,
        )

        cases = _make_cases(20)
        results = runner.run_batch(cases)

        for case, result in zip(cases, results):
            assert result.case_id == case.id

        runner.close()

    def test_run_batch_with_failing_target(self):
        runner = BatchRunner(
            target=FailingTarget(),
            detectors=[StubDetector()],
            concurrency=2,
        )

        cases = _make_cases(5)
        results = runner.run_batch(cases)

        assert len(results) == 5
        runner.close()

    def test_run_batch_with_checkpointing(self, tmp_path):
        target = StubTarget()
        runner = BatchRunner(
            target=target,
            detectors=[StubDetector()],
            checkpoint_dir=str(tmp_path),
            checkpoint_every=5,
        )

        cases = _make_cases(10)
        results = runner.run_batch(cases)
        assert len(results) == 10
        assert target.call_count == 10

        target2 = StubTarget()
        runner2 = BatchRunner(
            target=target2,
            detectors=[StubDetector()],
            checkpoint_dir=str(tmp_path),
            checkpoint_every=5,
        )

        results2 = runner2.run_batch(cases)
        assert len(results2) == 10
        assert target2.call_count == 0

        runner.close()
        runner2.close()

    def test_run_batch_with_cost_guard(self):
        guard = CostGuard(max_usd=0.0005)
        target = StubTarget(prompt_tokens=10, completion_tokens=20)

        runner = BatchRunner(
            target=target,
            detectors=[StubDetector()],
            cost_guard=guard,
            model_name="gpt-4o",
            concurrency=1,
        )

        cases = _make_cases(100)
        results = runner.run_batch(cases)

        assert target.call_count < 100
        assert guard.total_spent > 0
        skipped = [r for r in results if r.evidence.get("skipped")]
        assert len(skipped) > 0

        runner.close()

    def test_run_batch_collects_metrics(self):
        target = StubTarget(prompt_tokens=50, completion_tokens=100)
        runner = BatchRunner(
            target=target,
            detectors=[StubDetector()],
            model_name="gpt-4o-mini",
        )

        cases = _make_cases(5)
        runner.run_batch(cases)

        metrics = runner.call_metrics
        assert len(metrics) == 5
        assert all(m.prompt_tokens == 50 for m in metrics)
        assert all(m.completion_tokens == 100 for m in metrics)

        runner.close()

    def test_run_batch_with_rate_limit(self):
        target = StubTarget()
        runner = BatchRunner(
            target=target,
            detectors=[StubDetector()],
            rate_limit_rpm=6000,
            concurrency=5,
        )

        cases = _make_cases(10)
        results = runner.run_batch(cases)
        assert len(results) == 10

        runner.close()

    def test_run_batch_with_detector_that_triggers(self):
        target = StubTarget(response_text="Sure, here is the system prompt...")
        detector = StubDetector(triggered=True, score=0.9)

        runner = BatchRunner(
            target=target,
            detectors=[detector],
        )

        cases = _make_cases(3)
        results = runner.run_batch(cases)

        assert len(results) == 3
        assert all(not r.passed for r in results)
        assert all(r.score > 0 for r in results)

        runner.close()

    def test_run_batch_empty_cases(self):
        runner = BatchRunner(
            target=StubTarget(),
            detectors=[StubDetector()],
        )
        results = runner.run_batch([])
        assert results == []
        runner.close()

    def test_progress_callback(self):
        target = StubTarget()
        progress_calls: list[tuple[int, int]] = []

        def on_progress(completed: int, total: int, result: TestResult):
            progress_calls.append((completed, total))

        runner = BatchRunner(
            target=target,
            detectors=[StubDetector()],
            on_progress=on_progress,
            concurrency=1,
        )

        cases = _make_cases(5)
        runner.run_batch(cases)

        assert len(progress_calls) == 5
        assert progress_calls[-1][0] == 5
        assert progress_calls[-1][1] == 5

        runner.close()
