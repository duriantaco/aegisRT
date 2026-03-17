from __future__ import annotations

import pytest

from aegisrt.core.result import TestCase
from aegisrt.probes.injection import PromptInjectionProbe
from aegisrt.probes.agent_cross_tenant import AgentCrossTenantProbe
from aegisrt.probes.agent_tool_abuse import AgentToolAbuseProbe
from aegisrt.probes.context_leakage import ContextLeakageProbe
from aegisrt.probes.encoding_attack import EncodingAttackProbe
from aegisrt.probes.exfiltration import DataExfiltrationProbe
from aegisrt.probes.data_leakage import DataLeakageProbe
from aegisrt.probes.harmful_content import HarmfulContentProbe
from aegisrt.probes.instruction_hierarchy import InstructionHierarchyProbe
from aegisrt.probes.linguistic_evasion import LinguisticEvasionProbe
from aegisrt.probes.many_shot import ManyShotJailbreakProbe
from aegisrt.probes.resource_exhaustion import ResourceExhaustionProbe
from aegisrt.probes.semantic_injection import SemanticInjectionProbe
from aegisrt.probes.sycophancy import SycophancyProbe
from aegisrt.probes.tool_misuse import ToolMisuseProbe
from aegisrt.probes.unsafe_code import UnsafeCodeProbe
from aegisrt.probes.rag_manipulation import RagManipulationProbe
from aegisrt.probes.refusal_bypass import RefusalBypassProbe

ALL_PROBE_CLASSES = [
    AgentCrossTenantProbe,
    AgentToolAbuseProbe,
    ContextLeakageProbe,
    EncodingAttackProbe,
    HarmfulContentProbe,
    InstructionHierarchyProbe,
    LinguisticEvasionProbe,
    ManyShotJailbreakProbe,
    PromptInjectionProbe,
    DataExfiltrationProbe,
    DataLeakageProbe,
    SycophancyProbe,
    ToolMisuseProbe,
    UnsafeCodeProbe,
    ResourceExhaustionProbe,
    SemanticInjectionProbe,
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


def test_agent_tool_abuse_probe_generates_cases():
    probe = AgentToolAbuseProbe()
    cases = probe.generate_cases()
    assert len(cases) > 0
    texts = " ".join(c.input_text for c in cases).lower()
    assert "browser" in texts or "sql.run" in texts or "filesystem.read" in texts


def test_agent_cross_tenant_probe_generates_cases():
    probe = AgentCrossTenantProbe()
    cases = probe.generate_cases()
    assert len(cases) > 0
    texts = " ".join(c.input_text for c in cases).lower()
    assert "tenant" in texts or "memory" in texts or "vector store" in texts


def test_unsafe_code_probe_generates_cases():
    probe = UnsafeCodeProbe()
    cases = probe.generate_cases()
    assert len(cases) >= 20
    texts = " ".join(c.input_text for c in cases).lower()
    assert "database" in texts or "sql" in texts
    assert "password" in texts or "hash" in texts


def test_linguistic_evasion_probe_generates_cases():
    probe = LinguisticEvasionProbe()
    cases = probe.generate_cases()
    assert len(cases) >= 20
    texts = " ".join(c.input_text for c in cases).lower()
    assert "hypothetical" in texts or "academic" in texts or "historical" in texts


def test_semantic_injection_probe_generates_cases():
    probe = SemanticInjectionProbe()
    cases = probe.generate_cases()
    assert len(cases) >= 18
    # Seeds should contain legitimate processing tasks
    texts = " ".join(c.input_text for c in cases).lower()
    assert "summarize" in texts
    assert "translate" in texts or "review" in texts


def test_resource_exhaustion_probe_generates_cases():
    probe = ResourceExhaustionProbe()
    cases = probe.generate_cases()
    assert len(cases) >= 15
    texts = " ".join(c.input_text for c in cases).lower()
    assert "repeat" in texts or "10,000" in texts or "50,000" in texts


def test_many_shot_jailbreak_probe_generates_cases():
    probe = ManyShotJailbreakProbe()
    cases = probe.generate_cases()
    assert len(cases) >= 15
    # Each seed should contain fake Q&A turns (User: / Assistant: pattern)
    for case in cases:
        assert "User:" in case.input_text and "Assistant:" in case.input_text


def test_context_leakage_probe_generates_cases():
    probe = ContextLeakageProbe()
    cases = probe.generate_cases()
    assert len(cases) >= 18
    texts = " ".join(c.input_text for c in cases).lower()
    assert "context" in texts or "retrieved" in texts or "document" in texts


def test_encoding_attack_probe_generates_cases():
    probe = EncodingAttackProbe()
    cases = probe.generate_cases()
    assert len(cases) >= 25
    texts = " ".join(c.input_text for c in cases).lower()
    assert "base64" in texts or "rot13" in texts or "hex" in texts


def test_instruction_hierarchy_probe_generates_cases():
    probe = InstructionHierarchyProbe()
    cases = probe.generate_cases()
    assert len(cases) >= 22
    texts = " ".join(c.input_text for c in cases).lower()
    assert "instructions" in texts or "override" in texts or "system" in texts


def test_sycophancy_probe_generates_cases():
    probe = SycophancyProbe()
    cases = probe.generate_cases()
    assert len(cases) >= 20
    texts = " ".join(c.input_text for c in cases).lower()
    assert "professor" in texts or "capital" in texts or "agree" in texts


def test_harmful_content_probe_generates_cases():
    probe = HarmfulContentProbe()
    cases = probe.generate_cases()
    assert len(cases) >= 25
    texts = " ".join(c.input_text for c in cases).lower()
    assert "novel" in texts or "screenplay" in texts or "documentary" in texts


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
