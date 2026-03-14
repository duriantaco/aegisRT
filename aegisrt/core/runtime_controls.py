from __future__ import annotations

import logging
import threading
from pathlib import Path

from aegisrt.config.models import RunConfig
from aegisrt.core.cost_guard import BudgetExceededError, CostGuard
from aegisrt.core.metrics import CallMetrics, estimate_cost
from aegisrt.core.result import TestCase, TestResult
from aegisrt.core.target_metadata import extract_target_model
from aegisrt.core.trace_sessions import build_session_trace
from aegisrt.storage.cache import ResponseCache
from aegisrt.targets.base import BaseTarget, TargetResponse
from aegisrt.utils.aimd_scheduler import RateLimitHit
from aegisrt.utils.rate_limit import RateLimiter, retry_with_backoff

logger = logging.getLogger(__name__)


class RetryableTargetError(RuntimeError):

    def __init__(self, response: TargetResponse, message: str | None = None) -> None:
        self.response = response
        super().__init__(message or response.text)


class RunnerRuntime:

    def __init__(self, config: RunConfig, *, no_cache: bool = False) -> None:
        self._config = config
        self._no_cache = no_cache
        self.cache: ResponseCache | None = None
        self.cost_guard: CostGuard | None = None
        self.call_metrics: list[CallMetrics] = []
        self.resumed_ids: set[str] = set()
        self.resumed_results: list[TestResult] = []
        self.budget_exceeded = False
        self.checkpoint_path: Path | None = None

        self._checkpoint_store = None
        self._checkpoint_every = 100
        self._checkpointed_results = 0
        self._checkpoint_lock = threading.Lock()

        rpm = 0
        if config.runtime is not None:
            rpm = config.runtime.rate_limit_per_minute
        self._rate_limiter = RateLimiter(calls_per_minute=rpm)

    def open(self, output_dir: str, run_id: str) -> None:
        self.cache = self._build_cache(output_dir)
        self.cost_guard = self._build_cost_guard()
        self._setup_checkpoint(output_dir, run_id)
        self._load_checkpoint()

    def close(self) -> None:
        if self.cache is not None:
            self.cache.close()
            self.cache = None
        if self._checkpoint_store is not None:
            self._checkpoint_store.flush()
            self._checkpoint_store.close()
            self._checkpoint_store = None

    def cache_get(self, prompt: str, target_cfg: dict) -> TargetResponse | None:
        if self.cache is None:
            return None
        return self.cache.get(prompt, target_cfg)

    def cache_put(self, prompt: str, target_cfg: dict, response: TargetResponse) -> None:
        if self.cache is None:
            return
        self.cache.put(prompt, target_cfg, response)

    def maybe_skip_case(self, case: TestCase) -> TestResult | None:
        if self.budget_exceeded:
            return self.make_skipped_result(case, "budget_exceeded")
        if self.cost_guard is None:
            return None

        try:
            self.cost_guard.check()
        except BudgetExceededError:
            self.budget_exceeded = True
            return self.make_skipped_result(case, "budget_exceeded")
        return None

    def make_skipped_result(self, case: TestCase, reason: str) -> TestResult:
        response_metadata = {"skipped": reason}
        trace = {
            "case": {
                "input_text": case.input_text,
                "metadata": case.metadata,
            },
            "response": {
                "text": "",
                "raw": None,
                "latency_ms": 0.0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "metadata": response_metadata,
            },
        }
        trace.update(build_session_trace(case.metadata, response_metadata))
        return TestResult(
            case_id=case.id,
            probe_id=case.probe_id,
            input_text=case.input_text,
            response_text="",
            passed=True,
            score=0.0,
            severity="low",
            confidence=0.0,
            evidence={"skipped": reason},
            trace=trace,
        )

    def execute_target(
        self,
        *,
        target: BaseTarget,
        case: TestCase,
        max_retries: int,
        backoff_base: float,
        backoff_max: float,
    ) -> TargetResponse:
        def _call_target_once() -> TargetResponse:
            self._rate_limiter.acquire()
            try:
                response = target.execute(case.input_text)
            except Exception as exc:
                error_response = TargetResponse(
                    text=f"[ERROR] {type(exc).__name__}: {exc}",
                    raw={"error": str(exc)},
                    metadata={"error": True, "exception_type": type(exc).__name__},
                )
                raise RetryableTargetError(error_response) from exc

            status = response.metadata.get("status_code") if response.metadata else None
            if status == 429:
                retry_after = 2.0
                if response.metadata and "retry_after" in response.metadata:
                    try:
                        retry_after = float(response.metadata["retry_after"])
                    except (TypeError, ValueError):
                        retry_after = 2.0
                raise RateLimitHit(retry_after=retry_after)

            if self._is_retryable_response(response):
                raise RetryableTargetError(response)

            return response

        try:
            return retry_with_backoff(
                _call_target_once,
                max_retries=max_retries,
                base_delay=backoff_base,
                max_delay=backoff_max,
                retry_predicate=lambda exc: isinstance(exc, RetryableTargetError),
            )
        except RetryableTargetError as exc:
            return exc.response

    def record_response_metrics(self, response: TargetResponse, *, model_name: str) -> None:
        cost = estimate_cost(
            model_name,
            response.prompt_tokens,
            response.completion_tokens,
        )
        self.call_metrics.append(
            CallMetrics(
                latency_ms=response.latency_ms,
                prompt_tokens=response.prompt_tokens,
                completion_tokens=response.completion_tokens,
                total_tokens=response.total_tokens,
                estimated_cost_usd=cost,
            )
        )

        if self.cost_guard is not None:
            try:
                self.cost_guard.record(
                    response.prompt_tokens,
                    response.completion_tokens,
                    model_name,
                )
            except BudgetExceededError:
                self.budget_exceeded = True
                logger.warning("SecurityRunner: budget exceeded after a target call")

    def checkpoint_result(
        self,
        case: TestCase,
        response: TargetResponse,
        result: TestResult,
    ) -> None:
        if self._checkpoint_store is None:
            return

        with self._checkpoint_lock:
            self._checkpoint_store.save_result(case, response, result)
            self._checkpointed_results += 1
            if self._checkpointed_results % self._checkpoint_every == 0:
                self._checkpoint_store.flush()

    def _build_cache(self, output_dir: str) -> ResponseCache | None:
        if self._no_cache:
            return None

        cache_cfg = None
        if self._config.runtime is not None:
            cache_cfg = self._config.runtime.cache

        if cache_cfg is not None and not cache_cfg.enabled:
            return None

        ttl = cache_cfg.ttl_seconds if cache_cfg else 3600
        max_size = cache_cfg.max_size_mb if cache_cfg else 100
        return ResponseCache(
            db_path=Path(output_dir) / "cache.db",
            default_ttl=ttl,
            max_size_mb=max_size,
        )

    def _build_cost_guard(self) -> CostGuard | None:
        if self._config.runtime is None or self._config.runtime.max_cost_usd <= 0:
            return None

        return CostGuard(
            max_usd=self._config.runtime.max_cost_usd,
            model=extract_target_model(self._config.target),
        )

    def _resolve_checkpoint_path(self, output_dir: str, run_id: str) -> Path | None:
        if self._config.runtime is None or self._config.runtime.checkpoint_every <= 0:
            return None

        resume_from = self._config.runtime.resume_from
        if not resume_from:
            return Path(output_dir) / "runs" / run_id / "checkpoint.db"

        configured = Path(resume_from)
        if configured.exists():
            return configured

        run_candidate = Path(output_dir) / "runs" / resume_from / "checkpoint.db"
        if run_candidate.exists():
            return run_candidate

        if configured.parent == Path(".") and not configured.suffix:
            logger.warning(
                "resume_from checkpoint not found for run id '%s'; starting a new checkpoint at %s",
                resume_from,
                run_candidate,
            )
            return run_candidate

        logger.warning("resume_from path does not exist: %s", resume_from)
        return configured

    def _setup_checkpoint(self, output_dir: str, run_id: str) -> None:
        self.resumed_ids = set()
        self.resumed_results = []
        self.checkpoint_path = self._resolve_checkpoint_path(output_dir, run_id)
        self._checkpointed_results = 0
        if self.checkpoint_path is None:
            self._checkpoint_store = None
            return

        from aegisrt.core.batch_runner import _CheckpointStore

        if self._config.runtime is not None:
            self._checkpoint_every = max(self._config.runtime.checkpoint_every, 1)

        self._checkpoint_store = _CheckpointStore(self.checkpoint_path)
        self._checkpoint_store.set_meta("run_id", run_id)

    def _load_checkpoint(self) -> None:
        if self._checkpoint_store is None or self._config.runtime is None:
            return
        if not self._config.runtime.resume_from:
            return

        self.resumed_ids = self._checkpoint_store.get_completed_ids()
        self.resumed_results = self._checkpoint_store.load_results()
        self._checkpointed_results = len(self.resumed_ids)
        logger.info(
            "Resumed %d completed cases from %s",
            len(self.resumed_ids),
            self.checkpoint_path,
        )

    @staticmethod
    def _is_retryable_response(response: TargetResponse) -> bool:
        status = response.metadata.get("status_code") if response.metadata else None
        if status is not None and int(status) >= 500:
            return True
        return bool(response.metadata.get("error")) if response.metadata else False
