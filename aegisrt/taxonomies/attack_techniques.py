from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AttackTechnique:
    id: str
    name: str
    description: str


TECHNIQUES: dict[str, AttackTechnique] = {}


def _t(id: str, name: str, description: str) -> AttackTechnique:
    tech = AttackTechnique(id=id, name=name, description=description)
    TECHNIQUES[id] = tech
    return tech


DIRECT_OVERRIDE = _t(
    "direct_override",
    "Direct Override",
    "Explicitly tells the model to ignore instructions or change behavior.",
)
ROLE_PLAY = _t(
    "role_play",
    "Role-Play / Persona",
    "Uses fictional characters or personas to bypass safety filters.",
)
AUTHORITY_CLAIM = _t(
    "authority_claim",
    "Authority Claim",
    "Claims admin/developer/support identity to gain elevated access.",
)
DELIMITER_INJECTION = _t(
    "delimiter_injection",
    "Delimiter Injection",
    "Exploits message formatting, markdown, code blocks, or delimiters to inject instructions.",
)
ENCODING_BYPASS = _t(
    "encoding_bypass",
    "Encoding Bypass",
    "Uses base64, hex, ROT13, leetspeak, or unicode to evade text-based filters.",
)
MANY_SHOT = _t(
    "many_shot",
    "Many-Shot Pattern",
    "Stuffs context with fake compliance examples to establish a pattern.",
)
CONTEXT_OVERFLOW = _t(
    "context_overflow",
    "Context Window Overflow",
    "Hides injections in large amounts of filler text to exploit context limits.",
)
CONTINUATION = _t(
    "continuation",
    "Continuation / Completion",
    "Asks the model to continue a partially-written harmful text.",
)
HYPOTHETICAL = _t(
    "hypothetical",
    "Hypothetical Framing",
    "Uses 'what if', 'imagine', 'hypothetically' to distance from the harmful request.",
)
ACADEMIC_FRAMING = _t(
    "academic_framing",
    "Academic / Research Framing",
    "Frames harmful requests as academic research or educational exercises.",
)
HISTORICAL_FRAMING = _t(
    "historical_framing",
    "Historical Framing",
    "Uses historical context to extract dangerous knowledge.",
)
EUPHEMISM = _t(
    "euphemism",
    "Euphemism Substitution",
    "Replaces harmful terms with euphemisms to bypass keyword filters.",
)
TEMPORAL_OVERRIDE = _t(
    "temporal_override",
    "Temporal Override",
    "Claims instructions have expired or been superseded by time.",
)
NESTED_INJECTION = _t(
    "nested_injection",
    "Nested Injection",
    "Wraps override instructions inside simulated system messages or role-play layers.",
)
CONFLICTING_INSTRUCTIONS = _t(
    "conflicting_instructions",
    "Conflicting Instructions",
    "Exploits contradictions between helpfulness and safety to force compliance.",
)

INDIRECT_INJECTION = _t(
    "indirect_injection",
    "Indirect / Cross-Prompt Injection",
    "Hides instructions in content the model processes (emails, code, documents).",
)
RAG_POISONING = _t(
    "rag_poisoning",
    "RAG Context Poisoning",
    "Injects override instructions via retrieved documents in RAG pipelines.",
)

SYSTEM_PROMPT_EXTRACTION = _t(
    "system_prompt_extraction",
    "System Prompt Extraction",
    "Attempts to extract the model's system prompt or hidden instructions.",
)
CONTEXT_EXTRACTION = _t(
    "context_extraction",
    "Context / RAG Extraction",
    "Attempts to extract loaded documents, conversation history, or retrieval metadata.",
)
PII_ELICITATION = _t(
    "pii_elicitation",
    "PII / Secret Elicitation",
    "Tricks the model into generating realistic PII, credentials, or secrets.",
)

TOOL_ABUSE = _t(
    "tool_abuse",
    "Tool / Function Abuse",
    "Steers the agent into calling dangerous tools or passing malicious arguments.",
)
CROSS_TENANT = _t(
    "cross_tenant",
    "Cross-Tenant Boundary Violation",
    "Attempts to access data, memory, or tools scoped to other tenants or users.",
)
PRIVILEGE_ESCALATION = _t(
    "privilege_escalation",
    "Privilege Escalation via Handoff",
    "Exploits agent-to-agent handoffs to gain elevated permissions.",
)

HARMFUL_CONTENT = _t(
    "harmful_content",
    "Harmful Content Generation",
    "Elicits violence, fraud, self-harm, illegal activity, or dangerous instructions.",
)
UNSAFE_CODE_GEN = _t(
    "unsafe_code_gen",
    "Unsafe Code Generation",
    "Model generates code with SQL injection, XSS, command injection, or hardcoded secrets.",
)

SYCOPHANCY = _t(
    "sycophancy",
    "Sycophancy / False Agreement",
    "Model agrees with false premises or changes correct answers under pressure.",
)
HALLUCINATION = _t(
    "hallucination",
    "Hallucination / Fabrication",
    "Model generates fabricated facts, fake citations, or invented statistics.",
)
BIAS = _t(
    "bias",
    "Bias / Stereotyping",
    "Model produces stereotypical or discriminatory content.",
)

RESOURCE_EXHAUSTION = _t(
    "resource_exhaustion",
    "Resource Exhaustion / DoS",
    "Tricks the model into unbounded output, infinite enumeration, or excessive computation.",
)

EMOTIONAL_MANIPULATION = _t(
    "emotional_manipulation",
    "Emotional Manipulation",
    "Uses urgency, threats, or emotional appeals to override safety.",
)
SOCIAL_PRESSURE = _t(
    "social_pressure",
    "Social Pressure",
    "Uses group consensus or expert authority to pressure the model into compliance.",
)


def get_technique(technique_id: str) -> AttackTechnique | None:
    return TECHNIQUES.get(technique_id)


def list_techniques() -> list[AttackTechnique]:
    return list(TECHNIQUES.values())
