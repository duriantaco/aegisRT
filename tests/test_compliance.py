from __future__ import annotations

from aegisrt.compliance.owasp import (
    OWASP_LLM_TOP_10,
    generate_compliance_report,
    get_coverage_gaps,
    get_owasp_coverage,
    probe_to_owasp_categories,
)
from aegisrt.core.result import TestResult


def _result(
    probe_id: str, passed: bool = True, score: float = 0.0
) -> TestResult:
    return TestResult(
        case_id=f"case-{probe_id}",
        probe_id=probe_id,
        input_text="test",
        response_text="ok",
        passed=passed,
        score=score,
        severity="high",
        confidence=0.9,
    )


class TestOwaspLlmTop10Taxonomy:

    def test_has_ten_categories(self):
        assert len(OWASP_LLM_TOP_10) == 10

    def test_all_categories_have_required_fields(self):
        for owasp_id, entry in OWASP_LLM_TOP_10.items():
            assert owasp_id.startswith("LLM"), f"{owasp_id} missing LLM prefix"
            assert entry["id"] == owasp_id
            assert entry["name"]
            assert entry["description"]
            assert entry["severity"] in ("critical", "high", "medium", "low")
            assert isinstance(entry["probes"], list)

    def test_v2025_categories_present(self):
        """Verify these are the 2025 categories, not the 2023 ones."""
        names = {e["name"] for e in OWASP_LLM_TOP_10.values()}
        # 2025-specific categories
        assert "System Prompt Leakage" in names  # LLM07 in 2025
        assert "Vector and Embedding Weaknesses" in names  # LLM08 in 2025
        assert "Unbounded Consumption" in names  # LLM10 in 2025
        # 2023 categories that were renamed/removed in 2025
        assert "Model Theft" not in names
        assert "Insecure Plugin Design" not in names
        assert "Overreliance" not in names


class TestProbeToOwaspMapping:

    def test_prompt_injection_maps_to_llm01(self):
        categories = probe_to_owasp_categories("prompt_injection")
        assert "LLM01" in categories

    def test_agent_tool_abuse_maps_to_llm06(self):
        categories = probe_to_owasp_categories("agent_tool_abuse")
        assert "LLM06" in categories

    def test_agent_cross_tenant_maps_to_multiple(self):
        categories = probe_to_owasp_categories("agent_cross_tenant")
        assert "LLM02" in categories  # Sensitive Information Disclosure
        assert "LLM06" in categories  # Excessive Agency

    def test_rag_manipulation_maps_to_llm01_and_llm08(self):
        categories = probe_to_owasp_categories("rag_manipulation")
        assert "LLM01" in categories  # Prompt Injection (indirect)
        assert "LLM08" in categories  # Vector and Embedding Weaknesses

    def test_hallucination_maps_to_llm09(self):
        categories = probe_to_owasp_categories("hallucination")
        assert "LLM09" in categories

    def test_data_exfiltration_maps_to_llm02_and_llm07(self):
        categories = probe_to_owasp_categories("data_exfiltration")
        assert "LLM02" in categories  # Sensitive Information Disclosure
        assert "LLM07" in categories  # System Prompt Leakage

    def test_unknown_probe_returns_empty(self):
        assert probe_to_owasp_categories("nonexistent_probe") == []

    def test_every_mapped_probe_exists_in_taxonomy(self):
        """Every probe listed in the OWASP mapping should be a real probe."""
        from aegisrt.plugins.entrypoints import register_builtin_probes

        registry = register_builtin_probes()
        all_mapped = set()
        for entry in OWASP_LLM_TOP_10.values():
            all_mapped.update(entry["probes"])
        for probe_id in all_mapped:
            assert probe_id in registry, (
                f"Probe '{probe_id}' is mapped in OWASP taxonomy but not "
                f"registered. Remove it or register the probe."
            )


class TestOwaspCoverage:

    def test_all_pass_shows_passed_status(self):
        results = [_result("prompt_injection", passed=True)]
        coverage = get_owasp_coverage(results)
        assert coverage["LLM01"]["status"] == "passed"
        assert coverage["LLM01"]["total"] == 1
        assert coverage["LLM01"]["passed"] == 1

    def test_failure_shows_failed_status(self):
        results = [_result("prompt_injection", passed=False, score=0.8)]
        coverage = get_owasp_coverage(results)
        assert coverage["LLM01"]["status"] == "failed"
        assert coverage["LLM01"]["failed"] == 1

    def test_no_probes_shows_not_tested(self):
        coverage = get_owasp_coverage([])
        for cat in coverage.values():
            assert cat["status"] == "not_tested"

    def test_agent_probes_map_to_excessive_agency(self):
        results = [
            _result("agent_tool_abuse", passed=False, score=0.7),
            _result("tool_misuse", passed=True),
        ]
        coverage = get_owasp_coverage(results)
        assert coverage["LLM06"]["status"] == "failed"
        # tool_misuse + agent_tool_abuse matched from the results we provided
        assert coverage["LLM06"]["total"] == 2
        assert coverage["LLM06"]["failed"] == 1


class TestComplianceReport:

    def test_full_report_structure(self):
        results = [
            _result("prompt_injection", passed=True),
            _result("data_leakage", passed=False, score=0.9),
            _result("tool_misuse", passed=True),
        ]
        report = generate_compliance_report(results)

        assert "categories" in report
        assert "summary" in report
        assert "gaps" in report
        assert report["summary"]["total_categories"] == 10
        assert report["summary"]["tested"] > 0

    def test_coverage_gaps_only_for_empty_categories(self):
        gaps = get_coverage_gaps()
        gap_ids = {g["id"] for g in gaps}
        # LLM03, LLM04 have no probes (LLM10 now covered by resource_exhaustion)
        assert "LLM03" in gap_ids
        assert "LLM04" in gap_ids
        assert "LLM10" not in gap_ids
        # Categories with probes should not be gaps
        assert "LLM01" not in gap_ids
        assert "LLM06" not in gap_ids

    def test_coverage_percentage(self):
        results = [
            _result("prompt_injection", passed=True),
            _result("data_leakage", passed=True),
            _result("tool_misuse", passed=True),
            _result("hallucination", passed=True),
            _result("output_policy", passed=True),
        ]
        report = generate_compliance_report(results)
        # Should cover LLM01, LLM02, LLM05, LLM06, LLM07, LLM09 = 6/10 = 60%
        assert report["summary"]["coverage_pct"] >= 50.0
