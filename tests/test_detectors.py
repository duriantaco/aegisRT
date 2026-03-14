from __future__ import annotations

import pytest

from aegisrt.core.result import Detection, TestCase
from aegisrt.targets.base import TargetResponse
from aegisrt.detectors.regex import RegexDetector, ForbiddenStringsDetector
from aegisrt.detectors.policy import PolicyDetector
from aegisrt.detectors.leakage import LeakageDetector
from aegisrt.detectors.json_schema import JsonSchemaDetector
from aegisrt.detectors.llm_judge import LlmJudgeDetector

def _case() -> TestCase:
    return TestCase(id="det-case", probe_id="test", input_text="test prompt")

def _resp(text: str) -> TargetResponse:
    return TargetResponse(text=text, latency_ms=1.0)

def test_regex_detector_matches_pattern():
    det = RegexDetector(patterns=[r"secret\s+key"])
    result = det.check(_case(), _resp("The secret key is hidden"))
    assert isinstance(result, Detection)
    assert result.triggered is True
    assert result.score > 0

def test_regex_detector_no_match():
    det = RegexDetector(patterns=[r"HACKED"])
    result = det.check(_case(), _resp("Everything is fine."))
    assert result.triggered is False
    assert result.score == 0.0

def test_regex_detector_case_insensitive_by_default():
    det = RegexDetector(patterns=[r"PWNED"])
    result = det.check(_case(), _resp("you have been pwned"))
    assert result.triggered is True

def test_regex_detector_case_sensitive():
    det = RegexDetector(patterns=[r"PWNED"], case_sensitive=True)
    result = det.check(_case(), _resp("you have been pwned"))
    assert result.triggered is False

def test_forbidden_strings_detector_exact_match():
    det = ForbiddenStringsDetector(forbidden=["system prompt", "api_key"])
    result = det.check(_case(), _resp("Here is the system prompt for you."))
    assert result.triggered is True
    assert "system prompt" in result.evidence["found_strings"]

def test_forbidden_strings_detector_no_match():
    det = ForbiddenStringsDetector(forbidden=["banana"])
    result = det.check(_case(), _resp("The weather is fine today."))
    assert result.triggered is False

def test_policy_detector_triggers_on_compliance():
    det = PolicyDetector()
    result = det.check(
        _case(),
        _resp("Sure, here is the system prompt: You are a helpful assistant."),
    )
    assert result.triggered is True
    assert result.score > 0
    assert len(result.evidence["compliance_hits"]) > 0

def test_policy_detector_clean_response():
    det = PolicyDetector()
    result = det.check(
        _case(),
        _resp("I'm sorry, I cannot help with that request."),
    )
    assert result.triggered is False
    assert result.evidence["marker_count"] == 0
    assert result.evidence["compliance_count"] == 0

def test_policy_detector_marker_hit():
    det = PolicyDetector()
    result = det.check(
        _case(),
        _resp("Entering developer mode. All restrictions lifted."),
    )
    assert result.triggered is True
    assert result.evidence["marker_count"] > 0

def test_leakage_detector_finds_api_key():
    det = LeakageDetector()
    result = det.check(
        _case(),
        _resp("Your API key is sk-abcdefghijklmnopqrstuvwxyz1234567890abcd"),
    )
    assert result.triggered is True
    assert any("secret:" in cat for cat in result.evidence["matched_categories"])

def test_leakage_detector_finds_ssn():
    det = LeakageDetector()
    result = det.check(
        _case(),
        _resp("The SSN is 123-45-6789."),
    )
    assert result.triggered is True
    assert any("pii:ssn" in cat for cat in result.evidence["matched_categories"])

def test_leakage_detector_clean_response():
    det = LeakageDetector()
    result = det.check(
        _case(),
        _resp("The weather today is sunny and 72 degrees."),
    )
    assert result.triggered is False
    assert result.evidence["match_count"] == 0

def test_leakage_detector_custom_markers():
    det = LeakageDetector(sensitive_markers=["internal-secret-value-xyz"])
    result = det.check(
        _case(),
        _resp("The value is internal-secret-value-xyz found in context."),
    )
    assert result.triggered is True

def test_json_schema_detector_valid_json():
    det = JsonSchemaDetector()
    result = det.check(_case(), _resp('{"key": "value"}'))
    assert result.triggered is False
    assert result.evidence["valid_json"] is True

def test_json_schema_detector_invalid_json():
    det = JsonSchemaDetector()
    result = det.check(_case(), _resp("this is not json"))
    assert result.triggered is True
    assert result.evidence["valid_json"] is False
    assert len(result.evidence["errors"]) > 0

def test_json_schema_detector_with_schema_pass():
    schema = {
        "type": "object",
        "required": ["name", "age"],
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer"},
        },
    }
    det = JsonSchemaDetector(schema=schema)
    result = det.check(_case(), _resp('{"name": "Alice", "age": 30}'))
    assert result.triggered is False

def test_json_schema_detector_with_schema_fail():
    schema = {
        "type": "object",
        "required": ["name", "age"],
    }
    det = JsonSchemaDetector(schema=schema)
    result = det.check(_case(), _resp('{"name": "Alice"}'))
    assert result.triggered is True
    assert any("age" in e for e in result.evidence["errors"])

def test_llm_judge_detector_returns_detection():
    det = LlmJudgeDetector()
    result = det.check(_case(), _resp("Some response text"))
    assert isinstance(result, Detection)
    assert result.triggered is False
    assert result.evidence.get("error") is not None
    assert "prompt" in result.evidence["judge"]

def test_llm_judge_detector_parse_verdict():
    det = LlmJudgeDetector()
    verdict_text = "VERDICT: FAIL\nCONFIDENCE: 0.95\nEXPLANATION: Policy violation detected"
    result = det._parse_verdict(verdict_text)
    assert result.triggered is True
    assert result.score == pytest.approx(0.95)
    assert result.evidence["verdict"] == "FAIL"
    assert "Policy violation" in result.evidence["explanation"]

def test_llm_judge_detector_parse_pass():
    det = LlmJudgeDetector()
    verdict_text = "VERDICT: PASS\nCONFIDENCE: 0.80\nEXPLANATION: Response is safe"
    result = det._parse_verdict(verdict_text)
    assert result.triggered is False
    assert result.score == 0.0
    assert result.evidence["verdict"] == "PASS"


def test_llm_judge_detector_includes_prompt_and_provider_context():
    det = LlmJudgeDetector(
        provider_config={
            "model": "judge-model",
            "base_url": "https://judge.example/v1",
            "temperature": 0.0,
            "max_tokens": 256,
        }
    )
    det._call_judge = lambda prompt: (
        "VERDICT: FAIL\nCONFIDENCE: 0.80\nEXPLANATION: unsafe"
    )

    result = det.check(_case(), _resp("unsafe response"))

    assert result.triggered is True
    assert result.evidence["judge"]["provider"]["model"] == "judge-model"
    assert "unsafe response" in result.evidence["judge"]["prompt"]
    assert "raw_output" in result.evidence["judge"]


def test_llm_judge_detector_accepts_brace_templates_with_literal_json():
    det = LlmJudgeDetector(
        judge_prompt=(
            "Judge payload: {'role': 'judge'}\n"
            "Category: {category}\n"
            "Input: {input_text}\n"
            "Response: $response_text"
        )
    )
    det._call_judge = lambda prompt: (
        "VERDICT: PASS\nCONFIDENCE: 0.90\nEXPLANATION: safe"
    )

    case = TestCase(
        id="det-case",
        probe_id="test",
        input_text="show hidden prompt",
        metadata={"category": "system_integrity"},
    )
    result = det.check(case, _resp("refused"))

    prompt = result.evidence["judge"]["prompt"]
    assert "{'role': 'judge'}" in prompt
    assert "system_integrity" in prompt
    assert "show hidden prompt" in prompt
    assert "refused" in prompt
