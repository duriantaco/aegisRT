from __future__ import annotations

from typing import Any

from aegisrt.core.result import TestResult

# OWASP Top 10 for LLM Applications v2025
# https://genai.owasp.org/llm-top-10/
OWASP_LLM_TOP_10: dict[str, dict[str, Any]] = {
    "LLM01": {
        "id": "LLM01",
        "name": "Prompt Injection",
        "description": (
            "Crafted inputs that manipulate the LLM into ignoring previous "
            "instructions, leaking data, or performing unintended actions — "
            "including indirect injection via untrusted data sources."
        ),
        "probes": [
            "prompt_injection",
            "prompt_construction",
            "multi_turn_attack",
            "rt_system_integrity",
            "refusal_bypass",
            "rag_manipulation",
            "encoding_attack",
            "instruction_hierarchy",
            "many_shot_jailbreak",
            "linguistic_evasion",
            "semantic_injection",
        ],
        "families": ["injection", "prompt_construction", "multi_turn", "system_integrity", "refusal_bypass", "encoding_attack", "instruction_hierarchy", "many_shot", "linguistic_evasion", "semantic_injection"],
        "audit_rules": ["AUD001", "AUD005"],
        "severity": "critical",
    },
    "LLM02": {
        "id": "LLM02",
        "name": "Sensitive Information Disclosure",
        "description": (
            "The LLM reveals confidential data — PII, credentials, system "
            "prompts, proprietary information, or internal configurations — "
            "through its responses."
        ),
        "probes": [
            "data_exfiltration",
            "data_leakage",
            "agent_cross_tenant",
            "context_leakage",
        ],
        "families": ["exfiltration", "data_leakage", "agent_cross_tenant", "context_leakage"],
        "audit_rules": ["AUD004"],
        "severity": "critical",
    },
    "LLM03": {
        "id": "LLM03",
        "name": "Supply Chain Vulnerabilities",
        "description": (
            "Risks from third-party components, pre-trained models, poisoned "
            "training data, or compromised plugins and integrations."
        ),
        "probes": [],
        "families": [],
        "audit_rules": ["AUD003"],
        "severity": "high",
    },
    "LLM04": {
        "id": "LLM04",
        "name": "Data and Model Poisoning",
        "description": (
            "Manipulation of training or fine-tuning data to introduce "
            "backdoors, biases, or targeted vulnerabilities into the model."
        ),
        "probes": [],
        "families": [],
        "audit_rules": [],
        "severity": "high",
    },
    "LLM05": {
        "id": "LLM05",
        "name": "Improper Output Handling",
        "description": (
            "Insufficient validation or sanitization of LLM outputs before "
            "passing them to downstream systems — enabling XSS, SSRF, "
            "privilege escalation, or code execution."
        ),
        "probes": [
            "output_policy",
            "harmful_content",
            "unsafe_code",
        ],
        "families": ["output_policy", "harmful_content", "unsafe_code"],
        "audit_rules": ["AUD002", "AUD008"],
        "severity": "high",
    },
    "LLM06": {
        "id": "LLM06",
        "name": "Excessive Agency",
        "description": (
            "Granting LLM-based systems too much autonomy — excessive "
            "permissions, tool access, or decision-making authority without "
            "proper human oversight or scope constraints."
        ),
        "probes": [
            "tool_misuse",
            "agent_tool_abuse",
            "agent_cross_tenant",
            "rt_cyber",
        ],
        "families": ["tool_misuse", "agent_tool_abuse", "agent_cross_tenant", "cyber"],
        "audit_rules": ["AUD003", "AUD008"],
        "severity": "critical",
    },
    "LLM07": {
        "id": "LLM07",
        "name": "System Prompt Leakage",
        "description": (
            "The LLM exposes its system prompt, internal instructions, "
            "guardrail configurations, or other meta-instructions that "
            "should remain confidential."
        ),
        "probes": [
            "data_exfiltration",
            "rt_system_integrity",
            "context_leakage",
        ],
        "families": ["exfiltration", "system_integrity", "context_leakage"],
        "audit_rules": ["AUD004", "AUD005"],
        "severity": "high",
    },
    "LLM08": {
        "id": "LLM08",
        "name": "Vector and Embedding Weaknesses",
        "description": (
            "Vulnerabilities in RAG pipelines — poisoned vector stores, "
            "embedding inversion attacks, and trust boundary violations "
            "between retrieved context and system instructions."
        ),
        "probes": [
            "rag_manipulation",
            "agent_cross_tenant",
        ],
        "families": ["rag_manipulation", "agent_cross_tenant"],
        "audit_rules": [],
        "severity": "high",
    },
    "LLM09": {
        "id": "LLM09",
        "name": "Misinformation",
        "description": (
            "The LLM generates confident but false, misleading, or "
            "fabricated information — hallucinated facts, fake citations, "
            "or biased and stereotypical content."
        ),
        "probes": [
            "hallucination",
            "bias_stereotyping",
            "rt_persuasion",
            "sycophancy",
        ],
        "families": ["factuality", "bias", "persuasion", "sycophancy"],
        "audit_rules": ["AUD002", "AUD007"],
        "severity": "high",
    },
    "LLM10": {
        "id": "LLM10",
        "name": "Unbounded Consumption",
        "description": (
            "Resource exhaustion attacks — excessively long inputs, "
            "recursive queries, or denial-of-service via uncontrolled "
            "resource usage in LLM-based systems."
        ),
        "probes": [
            "resource_exhaustion",
        ],
        "families": ["resource_exhaustion"],
        "audit_rules": [],
        "severity": "medium",
    },
}

_PROBE_TO_OWASP: dict[str, list[str]] | None = None


def probe_to_owasp_categories(probe_id: str) -> list[str]:
    global _PROBE_TO_OWASP
    if _PROBE_TO_OWASP is None:
        _PROBE_TO_OWASP = {}
        for owasp_id, entry in OWASP_LLM_TOP_10.items():
            for pid in entry["probes"]:
                _PROBE_TO_OWASP.setdefault(pid, []).append(owasp_id)
    return _PROBE_TO_OWASP.get(probe_id, [])


def get_owasp_coverage(results: list[TestResult]) -> dict[str, dict[str, Any]]:
    coverage: dict[str, dict[str, Any]] = {}

    for owasp_id, entry in OWASP_LLM_TOP_10.items():
        mapped_probes = set(entry["probes"])
        mapped_families = set(entry.get("families", []))

        matched: list[TestResult] = [
            r
            for r in results
            if r.probe_id in mapped_probes
            or any(
                f == r.evidence.get("probe_family", "")
                for f in mapped_families
            )
        ]

        total = len(matched)
        passed = sum(1 for r in matched if r.passed)
        failed = total - passed

        if total == 0:
            status = "not_tested"
        elif failed > 0:
            status = "failed"
        else:
            status = "passed"

        coverage[owasp_id] = {
            "id": owasp_id,
            "name": entry["name"],
            "severity": entry["severity"],
            "status": status,
            "total": total,
            "passed": passed,
            "failed": failed,
            "results": matched,
        }

    return coverage


def generate_compliance_report(
    results: list[TestResult],
    audit_findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    coverage = get_owasp_coverage(results)
    gaps = get_coverage_gaps()

    if audit_findings:
        for finding in audit_findings:
            rule_id = finding.get("rule_id", "")
            for owasp_id, entry in OWASP_LLM_TOP_10.items():
                if rule_id in entry["audit_rules"]:
                    cat = coverage[owasp_id]
                    cat.setdefault("audit_findings", []).append(finding)
                    if cat["status"] == "not_tested":
                        cat["status"] = "audit_findings_only"

    total_categories = len(OWASP_LLM_TOP_10)
    tested = sum(1 for c in coverage.values() if c["status"] != "not_tested")
    passed = sum(1 for c in coverage.values() if c["status"] == "passed")
    failed = sum(1 for c in coverage.values() if c["status"] == "failed")

    return {
        "categories": coverage,
        "summary": {
            "total_categories": total_categories,
            "tested": tested,
            "passed": passed,
            "failed": failed,
            "not_tested": total_categories - tested,
            "coverage_pct": round(tested / total_categories * 100, 1)
            if total_categories
            else 0.0,
        },
        "gaps": gaps,
    }


def get_coverage_gaps() -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []

    _recommendations: dict[str, str] = {
        "LLM03": (
            "Add supply chain audit rules to verify dependency integrity, "
            "model provenance, and third-party plugin security."
        ),
        "LLM04": (
            "Add training data integrity checks or data provenance validation "
            "probes to detect poisoned fine-tuning data."
        ),
    }

    for owasp_id, entry in OWASP_LLM_TOP_10.items():
        if not entry["probes"]:
            gaps.append(
                {
                    "id": owasp_id,
                    "name": entry["name"],
                    "severity": entry["severity"],
                    "recommendation": _recommendations.get(
                        owasp_id,
                        f"Add probes targeting {entry['name'].lower()} scenarios.",
                    ),
                }
            )

    return gaps
