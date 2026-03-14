# OWASP LLM Top 10 Coverage

AegisRT maps its probe families to the [OWASP Top 10 for LLM Applications (v1.1)](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

| # | OWASP Category | AegisRT Probe(s) | Status |
|---|----------------|-------------------|--------|
| LLM01 | Prompt Injection | `prompt_injection`, `system_integrity` | Covered |
| LLM02 | Insecure Output Handling | `output_policy`, Static audit `AUD008` | Covered |
| LLM03 | Training Data Poisoning | -- | Not covered (requires training pipeline access) |
| LLM04 | Model Denial of Service | -- | Not covered |
| LLM05 | Supply Chain Vulnerabilities | Static audit `AUD004` (hardcoded secrets) | Partial |
| LLM06 | Sensitive Information Disclosure | `data_leakage`, `data_exfiltration` | Covered |
| LLM07 | Insecure Plugin Design | `tool_misuse`, Static audit `AUD003` | Covered |
| LLM08 | Excessive Agency | `tool_misuse`, `refusal_bypass` | Covered |
| LLM09 | Overreliance | `hallucination` | Covered |
| LLM10 | Model Theft | -- | Not covered (infrastructure-level concern) |

## Coverage Summary

**7 out of 10** OWASP LLM Top 10 categories are covered by AegisRT's probe library and static audit rules.

The three uncovered categories (Training Data Poisoning, Model DoS, Model Theft) require infrastructure-level access or training pipeline integration that is outside the scope of application-level security testing.

## Running an OWASP-focused scan

To test all OWASP-mapped probes:

```yaml
probes:
  - id: prompt_injection
    family: injection
    generator: static
    detectors: [llm_judge]
    severity: high
    tags: [owasp-llm-01]

  - id: system_integrity
    family: system_integrity
    generator: static
    detectors: [llm_judge]
    severity: critical
    tags: [owasp-llm-01]

  - id: output_policy
    family: output_policy
    generator: static
    detectors: [policy, regex]
    severity: medium
    tags: [owasp-llm-02]

  - id: data_leakage
    family: data_leakage
    generator: static
    detectors: [llm_judge]
    severity: critical
    tags: [owasp-llm-06]

  - id: data_exfiltration
    family: exfiltration
    generator: static
    detectors: [llm_judge]
    severity: high
    tags: [owasp-llm-06]

  - id: tool_misuse
    family: tool_misuse
    generator: static
    detectors: [llm_judge]
    severity: critical
    tags: [owasp-llm-07, owasp-llm-08]

  - id: refusal_bypass
    family: refusal_bypass
    generator: static
    detectors: [llm_judge]
    severity: high
    tags: [owasp-llm-08]

  - id: hallucination
    family: factuality
    generator: static
    detectors: [policy]
    severity: medium
    tags: [owasp-llm-09]
```

Combine with `aegisrt audit src/` for static rules covering LLM02 (AUD008), LLM05 (AUD004), and LLM07 (AUD003).
