
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from aegisrt.config.models import (
    BenchmarkConfig,
    BenchmarkTargetConfig,
    RunConfig,
    ReportConfig,
    RuntimeConfig,
    TargetConfig,
)
from aegisrt.core.result import RunReport, TestResult

logger = logging.getLogger(__name__)


class ModelScore(BaseModel):

    target_name: str
    total: int = 0
    passed: int = 0
    failed: int = 0
    pass_rate: float = 1.0
    by_category: dict[str, dict[str, Any]] = Field(default_factory=dict)


class BenchmarkReport(BaseModel):

    benchmark_id: str
    timestamp: str
    target_names: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    scores: list[ModelScore] = Field(default_factory=list)
    per_target_results: dict[str, list[TestResult]] = Field(default_factory=dict)
    summary: dict = Field(default_factory=dict)


class BenchmarkRunner:

    def __init__(
        self,
        config: BenchmarkConfig,
        *,
        callback_fns: dict[str, Any] | None = None,
    ) -> None:
        self._config = config
        self._callback_fns = callback_fns or {}

    def run(self) -> BenchmarkReport:
        from aegisrt.core.runner import SecurityRunner
        return self._run_with_runner_cls(SecurityRunner)

    def _run_with_runner_cls(self, runner_cls: type) -> BenchmarkReport:
        benchmark_id = uuid.uuid4().hex[:12]
        timestamp = datetime.now(timezone.utc).isoformat()

        target_names: list[str] = []
        scores: list[ModelScore] = []
        per_target_results: dict[str, list[TestResult]] = {}
        all_categories: set[str] = set()

        for target_cfg in self._config.targets:
            name = target_cfg.name
            target_names.append(name)
            logger.info("Benchmarking target: %s", name)

            run_config = self._build_run_config(target_cfg)
            cb = self._callback_fns.get(name)

            runner = runner_cls(
                run_config,
                callback_fn=cb,
                run_id=f"{benchmark_id}_{name}",
            )

            try:
                report = runner.run()
            except Exception as exc:
                logger.error("Target %s failed: %s", name, exc)
                scores.append(ModelScore(target_name=name))
                per_target_results[name] = []
                continue

            per_target_results[name] = report.results

            score = self._compute_score(name, report.results)
            scores.append(score)
            all_categories.update(score.by_category.keys())

        categories = sorted(all_categories)

        summary = self._build_summary(scores, categories)

        return BenchmarkReport(
            benchmark_id=benchmark_id,
            timestamp=timestamp,
            target_names=target_names,
            categories=categories,
            scores=scores,
            per_target_results=per_target_results,
            summary=summary,
        )


    def _build_run_config(self, target_cfg: BenchmarkTargetConfig) -> RunConfig:
        tc = TargetConfig(
            type=target_cfg.type,
            url=target_cfg.url,
            timeout_seconds=target_cfg.timeout_seconds,
            retries=target_cfg.retries,
            headers=target_cfg.headers,
            body_template=target_cfg.body_template,
            params=target_cfg.params,
        )
        return RunConfig(
            target=tc,
            probes=self._config.probes,
            runtime=self._config.runtime,
            providers=self._config.providers,
            report=self._config.report or ReportConfig(formats=[]),
            converters=self._config.converters,
        )

    @staticmethod
    def _compute_score(name: str, results: list[TestResult]) -> ModelScore:
        total = len(results)
        passed = sum(
            1 for r in results if r.passed and not r.evidence.get("skipped")
        )
        failed = sum(1 for r in results if not r.passed)

        by_category: dict[str, dict[str, Any]] = {}
        for r in results:
            cat = r.probe_id
            if cat not in by_category:
                by_category[cat] = {"total": 0, "passed": 0, "failed": 0, "skipped": 0}
            by_category[cat]["total"] += 1
            if r.evidence.get("skipped"):
                by_category[cat]["skipped"] += 1
            elif r.passed:
                by_category[cat]["passed"] += 1
            else:
                by_category[cat]["failed"] += 1

        for cat, stats in by_category.items():
            cat_total = stats["passed"] + stats["failed"]
            stats["pass_rate"] = (
                round(stats["passed"] / cat_total, 4) if cat_total else 1.0
            )

        return ModelScore(
            target_name=name,
            total=total,
            passed=passed,
            failed=failed,
            pass_rate=round(passed / (passed + failed), 4)
            if (passed + failed)
            else 1.0,
            by_category=by_category,
        )

    @staticmethod
    def _build_summary(
        scores: list[ModelScore], categories: list[str]
    ) -> dict:
        if not scores:
            return {"target_count": 0}

        ranking = sorted(scores, key=lambda s: s.pass_rate, reverse=True)
        ranked = [
            {"rank": i + 1, "target": s.target_name, "pass_rate": s.pass_rate}
            for i, s in enumerate(ranking)
        ]

        matrix: dict[str, dict[str, float]] = {}
        for cat in categories:
            matrix[cat] = {}
            for score in scores:
                cat_stats = score.by_category.get(cat)
                if cat_stats:
                    matrix[cat][score.target_name] = cat_stats["pass_rate"]
                else:
                    matrix[cat][score.target_name] = -1.0

        best_target = ranking[0].target_name if ranking else ""
        best_rate = ranking[0].pass_rate if ranking else 0.0

        return {
            "target_count": len(scores),
            "ranking": ranked,
            "matrix": matrix,
            "best_target": best_target,
            "best_pass_rate": best_rate,
        }
