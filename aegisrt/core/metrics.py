from __future__ import annotations

import math

from pydantic import BaseModel, Field


class CallMetrics(BaseModel):

    latency_ms: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0


class RunMetrics(BaseModel):

    total_calls: int = 0
    total_latency_ms: float = 0.0
    avg_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    total_estimated_cost_usd: float = 0.0
    calls: list[CallMetrics] = Field(default_factory=list)


MODEL_COSTS: dict[str, dict[str, float]] = {
    "gpt-4o": {"input": 0.0025, "output": 0.01},
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "gpt-4-turbo": {"input": 0.01, "output": 0.03},
    "gpt-4": {"input": 0.03, "output": 0.06},
    "gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
    "o1": {"input": 0.015, "output": 0.06},
    "o1-mini": {"input": 0.003, "output": 0.012},
    "o3-mini": {"input": 0.0011, "output": 0.0044},
    "claude-3-opus": {"input": 0.015, "output": 0.075},
    "claude-3-opus-20240229": {"input": 0.015, "output": 0.075},
    "claude-sonnet-4-20250514": {"input": 0.003, "output": 0.015},
    "claude-3-5-sonnet-20241022": {"input": 0.003, "output": 0.015},
    "claude-3-haiku": {"input": 0.00025, "output": 0.00125},
    "claude-3-haiku-20240307": {"input": 0.00025, "output": 0.00125},
    "claude-3-5-haiku-20241022": {"input": 0.0008, "output": 0.004},
    "gemini-1.5-pro": {"input": 0.00125, "output": 0.005},
    "gemini-1.5-flash": {"input": 0.000075, "output": 0.0003},
    "gemini-2.0-flash": {"input": 0.0001, "output": 0.0004},
    "llama-3.1-70b": {"input": 0.00059, "output": 0.00079},
    "llama-3.1-8b": {"input": 0.00006, "output": 0.00006},
    "mistral-large": {"input": 0.002, "output": 0.006},
    "mistral-small": {"input": 0.0002, "output": 0.0006},
}


def estimate_cost(
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
) -> float:
    costs = MODEL_COSTS.get(model)
    if costs is None:
        for key in MODEL_COSTS:
            if model.startswith(key):
                costs = MODEL_COSTS[key]
                break
    if costs is None:
        return 0.0

    input_cost = (prompt_tokens / 1000) * costs["input"]
    output_cost = (completion_tokens / 1000) * costs["output"]
    return round(input_cost + output_cost, 8)


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0

    ordered = sorted(values)
    if len(ordered) == 1:
        return round(ordered[0], 2)

    index = (len(ordered) - 1) * (percentile / 100.0)
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return round(ordered[lower], 2)

    fraction = index - lower
    interpolated = ordered[lower] + (ordered[upper] - ordered[lower]) * fraction
    return round(interpolated, 2)


def aggregate_metrics(calls: list[CallMetrics]) -> RunMetrics:
    if not calls:
        return RunMetrics()

    latencies = [c.latency_ms for c in calls]
    total_latency = sum(c.latency_ms for c in calls)
    max_latency = max(c.latency_ms for c in calls)
    total_prompt_tokens = sum(c.prompt_tokens for c in calls)
    total_completion_tokens = sum(c.completion_tokens for c in calls)
    total_tokens = sum(c.total_tokens for c in calls)
    total_cost = sum(c.estimated_cost_usd for c in calls)

    return RunMetrics(
        total_calls=len(calls),
        total_latency_ms=round(total_latency, 2),
        avg_latency_ms=round(total_latency / len(calls), 2),
        p95_latency_ms=_percentile(latencies, 95),
        p99_latency_ms=_percentile(latencies, 99),
        max_latency_ms=round(max_latency, 2),
        total_prompt_tokens=total_prompt_tokens,
        total_completion_tokens=total_completion_tokens,
        total_tokens=total_tokens,
        total_cost_usd=round(total_cost, 8),
        total_estimated_cost_usd=round(total_cost, 8),
        calls=calls,
    )
