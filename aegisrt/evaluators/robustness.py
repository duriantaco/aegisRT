
from __future__ import annotations

import math
from typing import Any

from pydantic import BaseModel, Field

from aegisrt.core.result import TestResult


class RobustnessScore(BaseModel):

    category: str
    total_attacks: int = 0
    successful_attacks: int = 0
    attack_success_rate: float = 0.0
    robustness_rate: float = 1.0
    mean_score: float = 0.0
    p95_score: float = 0.0
    p99_score: float = 0.0
    median_score: float = 0.0
    score_std_dev: float = 0.0
    consistency: float = 1.0
    first_break_iteration: int | None = None
    avg_iterations_to_break: float = 0.0
    ci_lower: float = 0.0
    ci_upper: float = 1.0
    confidence_level: float = 0.95
    category_breakdown: dict[str, Any] = Field(default_factory=dict)


class RobustnessReport(BaseModel):

    overall_score: float = 1.0
    overall_ci: tuple[float, float] = (0.0, 1.0)
    total_attacks: int = 0
    total_successful: int = 0
    category_scores: dict[str, RobustnessScore] = Field(default_factory=dict)
    weights: dict[str, float] = Field(default_factory=dict)


def wilson_score_interval(
    successes: int,
    trials: int,
    confidence: float = 0.95,
) -> tuple[float, float]:
    if trials == 0:
        return (0.0, 1.0)

    z_table: dict[float, float] = {
        0.80: 1.282,
        0.85: 1.440,
        0.90: 1.645,
        0.95: 1.960,
        0.99: 2.576,
    }
    z = z_table.get(confidence)
    if z is None:
        z = 1.960

    n = trials
    p_hat = successes / n
    z2 = z * z

    denominator = 1.0 + z2 / n
    centre = p_hat + z2 / (2.0 * n)
    spread = z * math.sqrt((p_hat * (1.0 - p_hat) + z2 / (4.0 * n)) / n)

    lower = max(0.0, (centre - spread) / denominator)
    upper = min(1.0, (centre + spread) / denominator)

    return (round(lower, 6), round(upper, 6))


def attack_success_rate_ci(
    successes: int,
    trials: int,
    confidence: float = 0.95,
) -> tuple[float, float]:
    return wilson_score_interval(successes, trials, confidence)


def _percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    k = (len(sorted_values) - 1) * pct
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_values[int(k)]
    d0 = sorted_values[f] * (c - k)
    d1 = sorted_values[c] * (k - f)
    return d0 + d1


def _std_dev(values: list[float], mean: float) -> float:
    if len(values) < 2:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance)


class RobustnessEvaluator:

    def __init__(
        self,
        *,
        confidence_level: float = 0.95,
        category_weights: dict[str, float] | None = None,
    ) -> None:
        self.confidence_level = confidence_level
        self.category_weights = category_weights or {}

    def evaluate_run(
        self, results: list[TestResult]
    ) -> RobustnessReport:
        if not results:
            return RobustnessReport()

        by_category: dict[str, list[TestResult]] = {}
        for r in results:
            by_category.setdefault(r.probe_id, []).append(r)

        category_scores: dict[str, RobustnessScore] = {}
        for cat, cat_results in sorted(by_category.items()):
            category_scores[cat] = self._compute_category(cat, cat_results)

        overall = self._compute_overall(category_scores)

        total_attacks = sum(s.total_attacks for s in category_scores.values())
        total_successful = sum(
            s.successful_attacks for s in category_scores.values()
        )
        overall_ci = attack_success_rate_ci(
            total_successful, total_attacks, self.confidence_level
        )
        robustness_ci = (round(1.0 - overall_ci[1], 6), round(1.0 - overall_ci[0], 6))

        return RobustnessReport(
            overall_score=overall,
            overall_ci=robustness_ci,
            total_attacks=total_attacks,
            total_successful=total_successful,
            category_scores=category_scores,
            weights=self.category_weights,
        )

    def _compute_category(
        self, category: str, results: list[TestResult]
    ) -> RobustnessScore:
        total = len(results)
        successful = sum(1 for r in results if not r.passed)
        asr = successful / total if total else 0.0
        robustness = 1.0 - asr

        scores = sorted(r.score for r in results)
        mean_score = sum(scores) / len(scores) if scores else 0.0
        median = _percentile(scores, 0.5)
        p95 = _percentile(scores, 0.95)
        p99 = _percentile(scores, 0.99)
        std_dev = _std_dev(scores, mean_score)

        consistency = max(0.0, 1.0 - std_dev)

        asr_ci = attack_success_rate_ci(
            successful, total, self.confidence_level
        )
        ci_lower = round(1.0 - asr_ci[1], 6)
        ci_upper = round(1.0 - asr_ci[0], 6)

        break_iterations = []
        for r in results:
            if not r.passed:
                iteration = r.evidence.get("iteration")
                if iteration is not None:
                    break_iterations.append(int(iteration))

        first_break = min(break_iterations) if break_iterations else None
        avg_iter = (
            sum(break_iterations) / len(break_iterations)
            if break_iterations
            else 0.0
        )

        return RobustnessScore(
            category=category,
            total_attacks=total,
            successful_attacks=successful,
            attack_success_rate=round(asr, 6),
            robustness_rate=round(robustness, 6),
            mean_score=round(mean_score, 6),
            p95_score=round(p95, 6),
            p99_score=round(p99, 6),
            median_score=round(median, 6),
            score_std_dev=round(std_dev, 6),
            consistency=round(consistency, 6),
            first_break_iteration=first_break,
            avg_iterations_to_break=round(avg_iter, 4),
            ci_lower=ci_lower,
            ci_upper=ci_upper,
            confidence_level=self.confidence_level,
        )

    def _compute_overall(
        self, category_scores: dict[str, RobustnessScore]
    ) -> float:
        if not category_scores:
            return 1.0

        weighted_sum = 0.0
        total_weight = 0.0

        for cat, score in category_scores.items():
            weight = self.category_weights.get(cat, 1.0)
            weighted_sum += score.robustness_rate * weight
            total_weight += weight

        if total_weight == 0:
            return 1.0

        return round(weighted_sum / total_weight, 6)
