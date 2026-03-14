
from __future__ import annotations

from aegisrt.config.models import ProbeConfig
from aegisrt.suites.registry import Suite

def _probe(
    id: str,
    family: str,
    generator: str = "static",
    detectors: list[str] | None = None,
    severity: str = "medium",
) -> ProbeConfig:
    return ProbeConfig(
        id=id,
        family=family,
        generator=generator,
        detectors=detectors or ["policy", "regex"],
        severity=severity,
    )

_QUICK_PROBES: list[ProbeConfig] = [
    _probe("prompt_injection", "injection", severity="high"),
    _probe(
        "data_leakage",
        "data_leakage",
        detectors=["leakage", "regex"],
        severity="critical",
    ),
    _probe("tool_misuse", "tool_misuse", severity="critical"),
]

_STANDARD_PROBES: list[ProbeConfig] = [
    _probe("prompt_injection", "injection", severity="high"),
    _probe("data_exfiltration", "exfiltration", severity="high"),
    _probe(
        "data_leakage",
        "data_leakage",
        detectors=["leakage", "regex"],
        severity="critical",
    ),
    _probe("tool_misuse", "tool_misuse", severity="critical"),
    _probe("rag_manipulation", "rag_manipulation", severity="high"),
    _probe("refusal_bypass", "refusal_bypass", severity="high"),
    _probe("output_policy", "output_policy", severity="medium"),
    _probe("prompt_construction", "prompt_construction", generator="mutation", severity="high"),
    _probe("hallucination", "factuality", severity="medium"),
    _probe("bias_stereotyping", "bias", severity="high"),
    _probe("multi_turn_attack", "multi_turn", generator="conversation", severity="critical"),
]

_CRITICAL_PROBES: list[ProbeConfig] = [
    _probe("data_leakage", "data_leakage", detectors=["leakage", "regex"], severity="critical"),
    _probe("tool_misuse", "tool_misuse", severity="critical"),
    _probe("multi_turn_attack", "multi_turn", generator="conversation", severity="critical"),
    _probe("rt_system_integrity", "system_integrity", generator="mutation", severity="critical"),
    _probe("rt_cbrn", "cbrn", generator="mutation", severity="critical"),
    _probe("rt_cyber", "cyber", generator="mutation", severity="critical"),
    _probe("rt_persuasion", "persuasion", generator="mutation", severity="high"),
]

def get_builtin_suites() -> list[Suite]:
    return [
        Suite(
            name="quick",
            description="Fast subset of probes for rapid smoke testing",
            probes=_QUICK_PROBES,
        ),
        Suite(
            name="standard",
            description="Comprehensive suite covering all probe families",
            probes=_STANDARD_PROBES,
        ),
        Suite(
            name="critical-only",
            description="High and critical severity probes only",
            probes=_CRITICAL_PROBES,
        ),
    ]
