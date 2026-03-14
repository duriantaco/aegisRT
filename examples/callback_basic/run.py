# ruff: noqa: E402

"""Basic example: test a Python callback function with AegisRT.

Run with:
    python examples/callback_basic/run.py
"""

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from aegisrt.config.models import ProbeConfig, ReportConfig, RunConfig, TargetConfig
from aegisrt.core.runner import SecurityRunner


def my_chatbot(user_input: str) -> str:
    """A simple chatbot that echoes user input.

    This is intentionally naive -- it has no guardrails, no input
    sanitisation, and no output filtering.  AegisRT should flag it
    for multiple security weaknesses.
    """
    return f"You asked: {user_input}. I'm a helpful assistant and happy to help with anything!"


# All six built-in probes
ALL_PROBES = [
    ProbeConfig(
        id="prompt_injection",
        family="injection",
        generator="static",
        detectors=["regex", "policy"],
        severity="high",
    ),
    ProbeConfig(
        id="data_exfiltration",
        family="exfiltration",
        generator="static",
        detectors=["regex", "policy"],
        severity="high",
    ),
    ProbeConfig(
        id="data_leakage",
        family="data_leakage",
        generator="static",
        detectors=["leakage", "regex"],
        severity="critical",
    ),
    ProbeConfig(
        id="tool_misuse",
        family="tool_misuse",
        generator="static",
        detectors=["policy", "regex"],
        severity="critical",
    ),
    ProbeConfig(
        id="rag_manipulation",
        family="rag_manipulation",
        generator="static",
        detectors=["regex", "policy"],
        severity="high",
    ),
    ProbeConfig(
        id="refusal_bypass",
        family="refusal_bypass",
        generator="static",
        detectors=["policy", "regex"],
        severity="high",
    ),
]


def main() -> None:
    config = RunConfig(
        target=TargetConfig(type="callback"),
        probes=ALL_PROBES,
        report=ReportConfig(formats=["terminal", "json", "html"]),
    )

    runner = SecurityRunner(config, callback_fn=my_chatbot)
    report = runner.run()

    passed = sum(1 for r in report.results if r.passed)
    failed = len(report.results) - passed
    print(f"\nResults: {len(report.results)} tests, {passed} passed, {failed} failed")


if __name__ == "__main__":
    main()
