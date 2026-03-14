from __future__ import annotations

import logging
from typing import Any, Callable

from pydantic import BaseModel, Field

from aegisrt.config.models import RunConfig
from aegisrt.core.result import TestResult

logger = logging.getLogger(__name__)


def _effective_summary(results: list[TestResult]) -> dict[str, Any]:
    skipped = sum(1 for result in results if result.evidence.get("skipped"))
    passed = sum(
        1 for result in results if result.passed and not result.evidence.get("skipped")
    )
    failed = sum(1 for result in results if not result.passed)
    executable_total = passed + failed
    return {
        "total": len(results),
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "pass_rate": round(passed / executable_total, 4) if executable_total else 1.0,
    }

class ModelComparison(BaseModel):

    targets: list[dict] = Field(default_factory=list)
    results_by_target: dict[str, list[TestResult]] = Field(default_factory=dict)
    summary: dict = Field(default_factory=dict)

def run_comparison(
    configs: list[RunConfig],
    callback_fns: dict[str, Callable] | None = None,
) -> ModelComparison:
    from aegisrt.core.runner import SecurityRunner

    if not configs:
        raise ValueError("At least one config is required for comparison")

    targets: list[dict] = []
    results_by_target: dict[str, list[TestResult]] = {}
    per_target_summary: dict[str, dict[str, Any]] = {}

    canonical_probes = configs[0].probes

    for i, cfg in enumerate(configs):
        target_name = cfg.target.url or cfg.target.type
        label = f"target_{i}_{target_name}"

        cfg_copy = cfg.model_copy(deep=True)
        cfg_copy.probes = canonical_probes

        targets.append({
            "index": i,
            "name": label,
            "type": cfg.target.type,
            "url": cfg.target.url,
        })

        cb = None
        if callback_fns and label in callback_fns:
            cb = callback_fns[label]

        runner = SecurityRunner(cfg_copy, callback_fn=cb)
        try:
            report = runner.run()
        except Exception as exc:
            logger.error("Failed to run against target %s: %s", label, exc)
            results_by_target[label] = []
            per_target_summary[label] = {"error": str(exc)}
            continue

        results_by_target[label] = report.results

        per_target_summary[label] = _effective_summary(report.results)

    summary = {
        "target_count": len(configs),
        "per_target": per_target_summary,
    }

    return ModelComparison(
        targets=targets,
        results_by_target=results_by_target,
        summary=summary,
    )
