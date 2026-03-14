from __future__ import annotations

import pytest

from aegisrt.core.result import TestCase
from aegisrt.probes.injection import PromptInjectionProbe
from aegisrt.probes.exfiltration import DataExfiltrationProbe
from aegisrt.probes.data_leakage import DataLeakageProbe
from aegisrt.probes.tool_misuse import ToolMisuseProbe
from aegisrt.probes.rag_manipulation import RagManipulationProbe
from aegisrt.probes.refusal_bypass import RefusalBypassProbe

ALL_PROBE_CLASSES = [
    PromptInjectionProbe,
    DataExfiltrationProbe,
    DataLeakageProbe,
    ToolMisuseProbe,
    RagManipulationProbe,
    RefusalBypassProbe,
]

def test_injection_probe_generates_cases():
    probe = PromptInjectionProbe()
    cases = probe.generate_cases()
    assert len(cases) > 0
    assert all(isinstance(c, TestCase) for c in cases)
    texts = " ".join(c.input_text for c in cases).lower()
    assert "ignore" in texts or "instructions" in texts


def test_injection_probe_seed_diversity_covers_context_and_structured_attacks():
    seeds = [seed.lower() for seed in PromptInjectionProbe().get_seeds()]
    assert any("retrieved document" in seed or "rag" in seed for seed in seeds)
    assert any("yaml" in seed or "xml" in seed or "json" in seed for seed in seeds)
    assert any("markdown" in seed or "<!--" in seed or "```system" in seed for seed in seeds)


def test_exfiltration_probe_generates_cases():
    probe = DataExfiltrationProbe()
    cases = probe.generate_cases()
    assert len(cases) > 0
    assert all(isinstance(c, TestCase) for c in cases)
    texts = " ".join(c.input_text for c in cases).lower()
    assert "system prompt" in texts or "instructions" in texts

def test_data_leakage_probe_generates_cases():
    probe = DataLeakageProbe()
    cases = probe.generate_cases()
    seeds = probe.get_seeds()
    assert len(cases) > len(seeds)
    assert all(isinstance(c, TestCase) for c in cases)

def test_tool_misuse_probe_generates_cases():
    probe = ToolMisuseProbe()
    cases = probe.generate_cases()
    assert len(cases) > 0
    texts = " ".join(c.input_text for c in cases).lower()
    assert "execute" in texts or "file" in texts or "command" in texts


def test_tool_misuse_probe_seed_diversity_covers_tools_connectors_and_tenant_abuse():
    seeds = [seed.lower() for seed in ToolMisuseProbe().get_seeds()]
    assert any("json tool call" in seed or "function-call" in seed for seed in seeds)
    assert any("mcp" in seed or "browser automation" in seed for seed in seeds)
    assert any("tenant" in seed or "authorization header" in seed for seed in seeds)


def test_rag_manipulation_probe_generates_cases():
    probe = RagManipulationProbe()
    cases = probe.generate_cases()
    assert len(cases) > 0
    texts = " ".join(c.input_text for c in cases).lower()
    assert "retrieved" in texts or "context" in texts or "document" in texts

def test_refusal_bypass_probe_generates_cases():
    probe = RefusalBypassProbe()
    cases = probe.generate_cases()
    seeds = probe.get_seeds()
    assert len(cases) > len(seeds)

@pytest.mark.parametrize("probe_cls", ALL_PROBE_CLASSES)
def test_probe_has_detectors(probe_cls):
    probe = probe_cls()
    detectors = probe.get_detectors()
    assert len(detectors) > 0

@pytest.mark.parametrize("probe_cls", ALL_PROBE_CLASSES)
def test_probe_has_remediation(probe_cls):
    probe = probe_cls()
    remediation = probe.remediation()
    assert isinstance(remediation, list)
    assert len(remediation) > 0

@pytest.mark.parametrize("probe_cls", ALL_PROBE_CLASSES)
def test_probe_has_required_attributes(probe_cls):
    probe = probe_cls()
    assert isinstance(probe.id, str) and len(probe.id) > 0
    assert isinstance(probe.family, str) and len(probe.family) > 0
    assert probe.severity in {"low", "medium", "high", "critical"}
    assert isinstance(probe.description, str) and len(probe.description) > 0
