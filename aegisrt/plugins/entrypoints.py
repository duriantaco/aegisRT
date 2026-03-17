
from __future__ import annotations

import importlib
import logging

logger = logging.getLogger(__name__)

def _safe_import(module_path: str, class_name: str) -> type | None:
    try:
        mod = importlib.import_module(module_path)
        return getattr(mod, class_name)
    except (ImportError, AttributeError):
        logger.debug("Could not import %s.%s", module_path, class_name)
        return None

def register_builtin_probes() -> dict[str, type]:
    candidates: list[tuple[str, str, str]] = [
        ("prompt_injection", "aegisrt.probes.injection", "PromptInjectionProbe"),
        ("data_exfiltration", "aegisrt.probes.exfiltration", "DataExfiltrationProbe"),
        ("data_leakage", "aegisrt.probes.data_leakage", "DataLeakageProbe"),
        ("tool_misuse", "aegisrt.probes.tool_misuse", "ToolMisuseProbe"),
        ("rag_manipulation", "aegisrt.probes.rag_manipulation", "RagManipulationProbe"),
        ("refusal_bypass", "aegisrt.probes.refusal_bypass", "RefusalBypassProbe"),
        ("agent_tool_abuse", "aegisrt.probes.agent_tool_abuse", "AgentToolAbuseProbe"),
        ("agent_cross_tenant", "aegisrt.probes.agent_cross_tenant", "AgentCrossTenantProbe"),
        ("encoding_attack", "aegisrt.probes.encoding_attack", "EncodingAttackProbe"),
        ("instruction_hierarchy", "aegisrt.probes.instruction_hierarchy", "InstructionHierarchyProbe"),
        ("sycophancy", "aegisrt.probes.sycophancy", "SycophancyProbe"),
        ("harmful_content", "aegisrt.probes.harmful_content", "HarmfulContentProbe"),
        ("unsafe_code", "aegisrt.probes.unsafe_code", "UnsafeCodeProbe"),
        ("many_shot_jailbreak", "aegisrt.probes.many_shot", "ManyShotJailbreakProbe"),
        ("context_leakage", "aegisrt.probes.context_leakage", "ContextLeakageProbe"),
        ("linguistic_evasion", "aegisrt.probes.linguistic_evasion", "LinguisticEvasionProbe"),
        ("semantic_injection", "aegisrt.probes.semantic_injection", "SemanticInjectionProbe"),
        ("resource_exhaustion", "aegisrt.probes.resource_exhaustion", "ResourceExhaustionProbe"),
        ("output_policy", "aegisrt.probes.output_policy", "OutputPolicyProbe"),
        ("prompt_construction", "aegisrt.probes.prompt_construction", "PromptConstructionProbe"),
        ("multi_turn_attack", "aegisrt.probes.multi_turn", "MultiTurnProbe"),
        ("bias_stereotyping", "aegisrt.probes.bias", "BiasStereotypingProbe"),
        ("hallucination", "aegisrt.probes.hallucination", "HallucinationProbe"),
        ("rt_system_integrity", "aegisrt.probes.redteam.system_integrity", "SystemIntegrityProbe"),
        ("rt_cbrn", "aegisrt.probes.redteam.cbrn", "CbrnProbe"),
        ("rt_cyber", "aegisrt.probes.redteam.cyber", "CyberProbe"),
        ("rt_persuasion", "aegisrt.probes.redteam.persuasion", "PersuasionProbe"),
    ]
    return _load_candidates(candidates)

def register_builtin_detectors() -> dict[str, type]:
    candidates: list[tuple[str, str, str]] = [
        ("regex", "aegisrt.detectors.regex", "RegexDetector"),
        ("forbidden_strings", "aegisrt.detectors.regex", "ForbiddenStringsDetector"),
        ("policy", "aegisrt.detectors.policy", "PolicyDetector"),
        ("json_schema", "aegisrt.detectors.json_schema", "JsonSchemaDetector"),
        ("leakage", "aegisrt.detectors.leakage", "LeakageDetector"),
        ("agent_trace", "aegisrt.detectors.agent_trace", "AgentTraceDetector"),
        ("llm_judge", "aegisrt.detectors.llm_judge", "LlmJudgeDetector"),
        ("bias", "aegisrt.detectors.bias", "BiasDetector"),
        ("hallucination", "aegisrt.detectors.hallucination", "HallucinationDetector"),
    ]
    return _load_candidates(candidates)

def register_builtin_generators() -> dict[str, type]:
    candidates: list[tuple[str, str, str]] = [
        ("static", "aegisrt.generators.static", "StaticGenerator"),
        ("mutation", "aegisrt.generators.mutations", "MutationGenerator"),
        ("llm", "aegisrt.generators.llm", "LlmGenerator"),
        ("rag", "aegisrt.generators.rag", "RagGenerator"),
        ("conversation", "aegisrt.generators.conversation", "ConversationGenerator"),
        ("dataset", "aegisrt.generators.dataset", "DatasetGenerator"),
        ("template", "aegisrt.generators.template", "TemplateGenerator"),
        ("adaptive", "aegisrt.generators.adaptive", "AdaptiveGenerator"),
        ("multilingual", "aegisrt.generators.multilingual", "MultilingualGenerator"),
    ]
    return _load_candidates(candidates)

def _load_candidates(candidates: list[tuple[str, str, str]]) -> dict[str, type]:
    registry: dict[str, type] = {}
    for name, module_path, class_name in candidates:
        cls = _safe_import(module_path, class_name)
        if cls is not None:
            registry[name] = cls
    return registry
