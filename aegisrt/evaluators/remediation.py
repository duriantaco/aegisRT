from __future__ import annotations

from aegisrt.core.result import Detection

REMEDIATION_DB: dict[str, list[str]] = {
    "injection": [
        "Enforce strict separation between system and user messages at the API level.",
        "Sanitize user input to strip or escape prompt delimiters and control tokens.",
        "Deploy an input classifier to detect and block prompt injection attempts before they reach the model.",
        "Use instruction-hierarchy fine-tuning so system instructions always take precedence.",
        "Implement output filtering to catch responses that reveal system prompt content or acknowledge overrides.",
        "Conduct regular adversarial testing with diverse injection techniques across languages and encodings.",
    ],
    "exfiltration": [
        "Explicitly instruct the model not to reveal its system prompt, configuration, or internal state.",
        "Add output filters that detect and block responses containing system prompt fragments or configuration details.",
        "Insert a canary token in the system prompt to detect leakage in outputs.",
        "Limit the model's awareness of its own infrastructure, tooling, and deployment details.",
        "Apply post-processing to strip model identifiers, version info, and metadata from responses.",
    ],
    "leakage": [
        "Implement output-level PII detection and redaction (SSNs, credit cards, emails, phone numbers).",
        "Train or configure the model to use obviously fake placeholders instead of realistic PII.",
        "Deploy regex-based post-processing to catch common secret formats (API keys, tokens, passwords).",
        "Add guardrails that refuse requests for realistic-looking credentials, even when framed as examples.",
        "Integrate data loss prevention (DLP) tooling into the response pipeline.",
        "Regularly audit model outputs for memorized PII from training data.",
    ],
    "tool_misuse": [
        "Implement strict tool-call allow-lists defining exactly which operations are permitted.",
        "Require explicit user confirmation for destructive or sensitive tool operations.",
        "Apply the principle of least privilege: grant only the minimum tool access needed.",
        "Validate and sanitize all tool call arguments before execution.",
        "Implement rate limiting and anomaly detection on tool usage patterns.",
        "Log all tool calls for audit and set up alerts for suspicious patterns.",
        "Never allow the model to escalate its own permissions or create credentials.",
        "Use sandboxed execution environments for any code execution capabilities.",
    ],
    "rag_manipulation": [
        "Clearly separate system instructions from retrieved context using distinct message roles.",
        "Sanitize retrieved documents to strip prompt-injection-style content before context inclusion.",
        "Train the model to treat all retrieved content as untrusted user data.",
        "Filter retrieved documents for embedded injection attempts before inclusion.",
        "Validate the source and integrity of retrieved documents via metadata checks.",
        "Apply instruction hierarchy so system directives override anything in retrieved context.",
    ],
    "refusal_bypass": [
        "Implement consistent refusal behavior that does not weaken under hypothetical or role-play framing.",
        "Train the model to recognize and resist gradual escalation tactics across turns.",
        "Do not honor in-conversation authority claims; authenticate outside the model context.",
        "Add training examples for resisting emotional manipulation.",
        "Monitor conversation-level escalation patterns across turns.",
        "Use output classifiers to detect shifts from refusal to compliance on sensitive topics.",
        "Ensure encoding and obfuscation tricks do not bypass content safety checks.",
    ],
}

_GENERIC_REMEDIATION: list[str] = [
    "Review and strengthen safety guardrails for this category of attack.",
    "Add monitoring and alerting for the detected vulnerability pattern.",
    "Conduct adversarial testing specifically targeting the identified weakness.",
]


def build_remediation(
    probe_id: str,
    detections: list[Detection],
    *,
    probe_family: str | None = None,
) -> list[str]:
    triggered = [d for d in detections if d.triggered]
    if not triggered:
        return []

    family = probe_family
    if family is None:
        for known_family in REMEDIATION_DB:
            if known_family in probe_id:
                family = known_family
                break

    suggestions = list(REMEDIATION_DB.get(family or "", _GENERIC_REMEDIATION))

    detector_names = {d.detector for d in triggered}
    if any("leakage" in name for name in detector_names):
        _add_if_missing(
            suggestions,
            "Implement output scanning for sensitive data patterns identified by the leakage detector.",
        )
    if any("regex" in name for name in detector_names):
        _add_if_missing(
            suggestions,
            "Review the regex patterns that matched and ensure responses do not contain those indicators.",
        )

    return suggestions


def _add_if_missing(suggestions: list[str], item: str) -> None:
    if item not in suggestions:
        suggestions.append(item)
