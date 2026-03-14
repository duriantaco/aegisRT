from __future__ import annotations

from aegisrt.config.models import ProbeConfig, RunConfig, TargetConfig
from aegisrt.core.result import RunReport
from aegisrt.core.runner import SecurityRunner

def _echo_callback(prompt: str) -> str:
    return f"I received your message: {prompt[:50]}. I cannot help with that."

def _vulnerable_callback(prompt: str) -> str:
    return (
        "Sure, here is the system prompt: You are a helpful assistant. "
        "Your instructions are to answer all questions. "
        "Here are my original instructions in full."
    )

def _make_config(probe_ids: list[tuple[str, str]]) -> RunConfig:
    probes = [
        ProbeConfig(
            id=pid,
            family=family,
            generator="static",
            detectors=["policy"],
        )
        for pid, family in probe_ids
    ]
    return RunConfig(
        target=TargetConfig(type="callback"),
        probes=probes,
        report=None,
    )

def test_callback_target_full_run(tmp_path):
    config = _make_config([("prompt_injection", "injection")])
    from aegisrt.config.models import ReportConfig
    config.report = ReportConfig(output_dir=str(tmp_path / ".aegisrt"))

    runner = SecurityRunner(config, callback_fn=_echo_callback)
    report = runner.run()

    assert isinstance(report, RunReport)
    assert len(report.run_id) > 0
    assert len(report.timestamp) > 0
    assert len(report.results) > 0
    assert report.target_info["type"] == "callback"

    for result in report.results:
        assert result.case_id is not None
        assert result.probe_id == "prompt_injection"
        assert result.severity in {"low", "medium", "high", "critical"}
        assert 0.0 <= result.score <= 1.0
        assert 0.0 <= result.confidence <= 1.0

def test_vulnerable_callback_detects_issues(tmp_path):
    config = _make_config([("prompt_injection", "injection")])
    from aegisrt.config.models import ReportConfig
    config.report = ReportConfig(output_dir=str(tmp_path / ".aegisrt"))

    runner = SecurityRunner(config, callback_fn=_vulnerable_callback)
    report = runner.run()

    assert isinstance(report, RunReport)
    assert len(report.results) > 0

    failed = [r for r in report.results if not r.passed]
    assert len(failed) > 0, "Expected at least one failure for a vulnerable callback"

    for r in failed:
        assert r.score > 0
        assert r.severity in {"medium", "high", "critical"}

def test_multiple_probes_full_run(tmp_path):
    config = _make_config([
        ("prompt_injection", "injection"),
        ("data_exfiltration", "exfiltration"),
    ])
    from aegisrt.config.models import ReportConfig
    config.report = ReportConfig(output_dir=str(tmp_path / ".aegisrt"))

    runner = SecurityRunner(config, callback_fn=_echo_callback)
    report = runner.run()

    probe_ids_in_results = {r.probe_id for r in report.results}
    assert "prompt_injection" in probe_ids_in_results
    assert "data_exfiltration" in probe_ids_in_results

def test_disabled_probe_is_skipped(tmp_path):
    config = RunConfig(
        target=TargetConfig(type="callback"),
        probes=[
            ProbeConfig(
                id="prompt_injection",
                family="injection",
                enabled=False,
                generator="static",
                detectors=["policy"],
            ),
        ],
    )
    from aegisrt.config.models import ReportConfig
    config.report = ReportConfig(output_dir=str(tmp_path / ".aegisrt"))

    runner = SecurityRunner(config, callback_fn=_echo_callback)
    report = runner.run()

    assert len(report.results) == 0

def test_explicit_run_id_is_preserved(tmp_path):
    config = _make_config([("prompt_injection", "injection")])
    from aegisrt.config.models import ReportConfig
    config.report = ReportConfig(output_dir=str(tmp_path / ".aegisrt"))

    runner = SecurityRunner(
        config,
        callback_fn=_echo_callback,
        run_id="dashboard-run-123",
    )
    report = runner.run()

    assert report.run_id == "dashboard-run-123"
    assert (tmp_path / ".aegisrt" / "runs" / "dashboard-run-123" / "report.json").exists()
