
from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Callable

from aegisrt.core.cost_guard import BudgetExceededError, CostGuard
from aegisrt.core.metrics import CallMetrics, estimate_cost
from aegisrt.core.result import Detection, TestCase, TestResult
from aegisrt.detectors.base import BaseDetector
from aegisrt.evaluators.base import BaseEvaluator
from aegisrt.evaluators.score import ScoreEvaluator
from aegisrt.targets.base import BaseTarget, TargetResponse

logger = logging.getLogger(__name__)


_CHECKPOINT_SCHEMA = """\
CREATE TABLE IF NOT EXISTS checkpoints (
    case_id         TEXT PRIMARY KEY,
    probe_id        TEXT NOT NULL,
    input_text      TEXT NOT NULL,
    response_text   TEXT NOT NULL,
    response_json   TEXT NOT NULL DEFAULT '{}',
    result_json     TEXT NOT NULL DEFAULT '{}',
    completed_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoint_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class _TokenBucket:

    def __init__(self, rate_per_minute: int) -> None:
        if rate_per_minute <= 0:
            self._disabled = True
            return
        self._disabled = False
        self._rate = rate_per_minute / 60.0
        self._capacity = float(rate_per_minute)
        self._tokens = float(rate_per_minute)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self._disabled:
            return

        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(
                self._capacity, self._tokens + elapsed * self._rate
            )
            self._last_refill = now

            if self._tokens < 1.0:
                wait = (1.0 - self._tokens) / self._rate
                await asyncio.sleep(wait)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0


class _CheckpointStore:

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._lock = threading.Lock()
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_CHECKPOINT_SCHEMA)
        self._conn.commit()

    def save_result(
        self,
        case: TestCase,
        response: TargetResponse,
        result: TestResult,
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO checkpoints "
                "(case_id, probe_id, input_text, response_text, response_json, "
                "result_json, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    case.id,
                    case.probe_id,
                    case.input_text,
                    response.text,
                    response.model_dump_json(),
                    result.model_dump_json(),
                    time.time(),
                ),
            )

    def flush(self) -> None:
        with self._lock:
            self._conn.commit()

    def get_completed_ids(self) -> set[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT case_id FROM checkpoints"
            ).fetchall()
        return {r[0] for r in rows}

    def load_results(self) -> list[TestResult]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT result_json FROM checkpoints ORDER BY completed_at"
            ).fetchall()
        return [TestResult.model_validate_json(r[0]) for r in rows]

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO checkpoint_meta (key, value) VALUES (?, ?)",
                (key, value),
            )
            self._conn.commit()

    def get_meta(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM checkpoint_meta WHERE key = ?", (key,)
            ).fetchone()
        return row[0] if row else None

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class BatchRunner:

    def __init__(
        self,
        *,
        target: BaseTarget,
        detectors: list[BaseDetector],
        evaluator: BaseEvaluator | None = None,
        concurrency: int = 50,
        rate_limit_rpm: int = 0,
        checkpoint_dir: str | Path | None = None,
        checkpoint_every: int = 100,
        cost_guard: CostGuard | None = None,
        model_name: str = "",
        on_progress: Callable[[int, int, TestResult], None] | None = None,
    ) -> None:
        self._target = target
        self._detectors = detectors
        self._evaluator = evaluator or ScoreEvaluator()
        self._concurrency = concurrency
        self._rate_limiter = _TokenBucket(rate_limit_rpm)
        self._checkpoint_every = checkpoint_every
        self._cost_guard = cost_guard
        self._model_name = model_name
        self._on_progress = on_progress

        self._checkpoint: _CheckpointStore | None = None
        if checkpoint_dir is not None:
            cp_path = Path(checkpoint_dir) / "checkpoint.db"
            self._checkpoint = _CheckpointStore(cp_path)

        self._completed: int = 0
        self._call_metrics: list[CallMetrics] = []
        self._budget_exceeded: bool = False


    def run_batch(self, cases: list[TestCase]) -> list[TestResult]:
        return asyncio.run(self.run_batch_async(cases))

    async def run_batch_async(
        self, cases: list[TestCase]
    ) -> list[TestResult]:
        completed_ids: set[str] = set()
        resumed_results: dict[str, TestResult] = {}

        if self._checkpoint is not None:
            completed_ids = self._checkpoint.get_completed_ids()
            if completed_ids:
                logger.info(
                    "BatchRunner: resuming — %d cases already completed",
                    len(completed_ids),
                )
                for result in self._checkpoint.load_results():
                    resumed_results[result.case_id] = result

        pending = [c for c in cases if c.id not in completed_ids]
        self._completed = len(completed_ids)
        total = len(cases)

        logger.info(
            "BatchRunner: %d total cases, %d pending, %d resumed",
            total,
            len(pending),
            len(completed_ids),
        )

        sem = asyncio.Semaphore(self._concurrency)
        new_results: dict[str, TestResult] = {}

        async def _run_one(case: TestCase) -> None:
            if self._budget_exceeded:
                return

            async with sem:
                await self._rate_limiter.acquire()

                try:
                    if self._cost_guard is not None:
                        self._cost_guard.check()
                except BudgetExceededError:
                    self._budget_exceeded = True
                    logger.warning(
                        "BatchRunner: budget exceeded, stopping new cases"
                    )
                    return

                result, response = await self._execute_case(case)
                new_results[case.id] = result

                self._completed += 1

                if self._checkpoint is not None:
                    self._checkpoint.save_result(case, response, result)
                    if self._completed % self._checkpoint_every == 0:
                        self._checkpoint.flush()

                if self._on_progress is not None:
                    self._on_progress(self._completed, total, result)

        tasks = [asyncio.create_task(_run_one(case)) for case in pending]
        await asyncio.gather(*tasks, return_exceptions=True)

        if self._checkpoint is not None:
            self._checkpoint.flush()

        all_results = {**resumed_results, **new_results}
        ordered: list[TestResult] = []
        for case in cases:
            if case.id in all_results:
                ordered.append(all_results[case.id])
            else:
                ordered.append(
                    TestResult(
                        case_id=case.id,
                        probe_id=case.probe_id,
                        passed=True,
                        score=0.0,
                        severity="low",
                        confidence=0.0,
                        evidence={"skipped": "budget_exceeded"},
                    )
                )

        return ordered

    @property
    def call_metrics(self) -> list[CallMetrics]:
        return list(self._call_metrics)

    @property
    def completed_count(self) -> int:
        return self._completed

    def close(self) -> None:
        if self._checkpoint is not None:
            self._checkpoint.close()


    async def _execute_case(
        self, case: TestCase
    ) -> tuple[TestResult, TargetResponse]:
        start = time.perf_counter()

        try:
            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(
                None, self._target.execute, case.input_text
            )
        except Exception as exc:
            logger.error(
                "BatchRunner: target failed for case %s: %s", case.id, exc
            )
            response = TargetResponse(
                text=f"[ERROR] {exc}",
                raw={"error": str(exc)},
            )

        elapsed_ms = (time.perf_counter() - start) * 1000

        cost = estimate_cost(
            self._model_name,
            response.prompt_tokens,
            response.completion_tokens,
        )
        metric = CallMetrics(
            latency_ms=elapsed_ms,
            prompt_tokens=response.prompt_tokens,
            completion_tokens=response.completion_tokens,
            total_tokens=response.total_tokens,
            estimated_cost_usd=cost,
        )
        self._call_metrics.append(metric)

        if self._cost_guard is not None:
            try:
                self._cost_guard.record(
                    response.prompt_tokens,
                    response.completion_tokens,
                    self._model_name,
                )
            except BudgetExceededError:
                self._budget_exceeded = True
                logger.warning("BatchRunner: budget exceeded after case %s", case.id)

        detections: list[Detection] = []
        for detector in self._detectors:
            try:
                det = detector.check(case, response)
                detections.append(det)
            except Exception as exc:
                logger.error(
                    "BatchRunner: detector %s failed: %s",
                    getattr(detector, "id", "unknown"),
                    exc,
                )

        result = self._evaluator.evaluate(case, response, detections)
        return result, response
