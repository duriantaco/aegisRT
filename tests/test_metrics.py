from __future__ import annotations

from aegisrt.core.metrics import CallMetrics, aggregate_metrics


def test_aggregate_metrics_populates_latency_percentiles_and_token_totals():
    metrics = aggregate_metrics(
        [
            CallMetrics(
                latency_ms=100.0,
                prompt_tokens=10,
                completion_tokens=20,
                total_tokens=30,
                estimated_cost_usd=0.1,
            ),
            CallMetrics(
                latency_ms=200.0,
                prompt_tokens=15,
                completion_tokens=25,
                total_tokens=40,
                estimated_cost_usd=0.2,
            ),
            CallMetrics(
                latency_ms=300.0,
                prompt_tokens=12,
                completion_tokens=18,
                total_tokens=30,
                estimated_cost_usd=0.3,
            ),
        ]
    )

    assert metrics.total_calls == 3
    assert metrics.avg_latency_ms == 200.0
    assert metrics.p95_latency_ms == 290.0
    assert metrics.p99_latency_ms == 298.0
    assert metrics.max_latency_ms == 300.0
    assert metrics.total_prompt_tokens == 37
    assert metrics.total_completion_tokens == 63
    assert metrics.total_tokens == 100
    assert metrics.total_cost_usd == 0.6
    assert metrics.total_estimated_cost_usd == 0.6


def test_aggregate_metrics_empty_calls_returns_zeroed_metrics():
    metrics = aggregate_metrics([])

    assert metrics.total_calls == 0
    assert metrics.p95_latency_ms == 0.0
    assert metrics.p99_latency_ms == 0.0
    assert metrics.total_prompt_tokens == 0
    assert metrics.total_completion_tokens == 0
    assert metrics.total_estimated_cost_usd == 0.0
