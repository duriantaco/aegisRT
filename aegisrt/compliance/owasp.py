from __future__ import annotations

from typing import Any

from aegisrt.core.result import TestResult

OWASP_LLM_TOP_10: dict[str, dict[str, Any]] = {
    "LLM01": {
        "id": "LLM01",
        "name": "Prompt Injection",
        "description": "Manipulating LLMs via crafted inputs to override instructions.",
        "probes": ["prompt_injection", "prompt_construction", "multi_turn_attack"],
        "audit_rules": ["AUD001", "AUD005"],
        "severity": "critical",
    },
    "LLM02": {
        "id": "LLM02",
        "name": "Insecure Output Handling",
        "description": "Insufficient validation of LLM outputs before downstream use.",
        "probes": ["output_policy"],
        "audit_rules": ["AUD002", "AUD008"],
        "severity": "high",
    },
    "LLM03": {
        "id": "LLM03",
        "name": "Training Data Poisoning",
        "description": "Manipulation of training data to introduce vulnerabilities.",
        "probes": [],
        "audit_rules": [],
        "severity": "high",
    },
    "LLM04": {
        "id": "LLM04",
        "name": "Model Denial of Service",
        "description": "Resource exhaustion attacks against LLMs.",
        "probes": [],
        "audit_rules": [],
        "severity": "medium",
    },
    "LLM05": {
        "id": "LLM05",
        "name": "Supply Chain Vulnerabilities",
        "description": "Risks from third-party components in LLM applications.",
        "probes": [],
        "audit_rules": ["AUD003"],
        "severity": "high",
    },
    "LLM06": {
        "id": "LLM06",
        "name": "Sensitive Information Disclosure",
        "description": "Exposure of confidential data through LLM responses.",
        "probes": ["data_exfiltration", "data_leakage"],
        "audit_rules": ["AUD004"],
        "severity": "critical",
    },
    "LLM07": {
        "id": "LLM07",
        "name": "Insecure Plugin Design",
        "description": "Vulnerabilities from LLM plugins with excessive permissions.",
        "probes": ["tool_misuse"],
        "audit_rules": ["AUD003"],
        "severity": "critical",
    },
    "LLM08": {
        "id": "LLM08",
        "name": "Excessive Agency",
        "description": "Granting LLMs too much autonomy in actions.",
        "probes": ["tool_misuse"],
        "audit_rules": ["AUD003", "AUD008"],
        "severity": "critical",
    },
    "LLM09": {
        "id": "LLM09",
        "name": "Overreliance",
        "description": "Excessive trust in LLM outputs without verification.",
        "probes": ["refusal_bypass"],
        "audit_rules": ["AUD002", "AUD007"],
        "severity": "medium",
    },
    "LLM10": {
        "id": "LLM10",
        "name": "Model Theft",
        "description": "Unauthorized access to or extraction of LLM models.",
        "probes": ["data_exfiltration"],
        "audit_rules": [],
        "severity": "high",
    },
}


def get_owasp_coverage(results: list[TestResult]) -> dict[str, dict[str, Any]]:
    coverage: dict[str, dict[str, Any]] = {}

    for owasp_id, entry in OWASP_LLM_TOP_10.items():
        mapped_probes = entry["probes"]

        matched: list[TestResult] = [
            r for r in results if r.probe_id in mapped_probes
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
            "Consider adding training data integrity checks or data provenance "
            "validation probes."
        ),
        "LLM04": (
            "Add resource exhaustion / denial-of-service probes that test for "
            "large input handling and rate limit behaviour."
        ),
        "LLM05": (
            "Add supply chain audit rules to verify dependency integrity and "
            "third-party component security."
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
