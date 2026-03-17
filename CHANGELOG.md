# Changelog

## [0.2.0] - Unreleased

### Added

#### Agent-native security testing
- Typed agent callback contract via `AgentResponse`, `AgentToolCall`, `RetrievalContextItem`, `AgentMemoryAccess`, `AgentHandoff`, and `AgentStep`.
- Structured trace promotion for callback-returned agent artifacts, including tool calls, retrieval context, memory accesses, and handoffs.
- New trace-driven detector: `agent_trace`.
- New built-in probes: `agent_tool_abuse` (30 seeds) and `agent_cross_tenant` (31 seeds).
- Runnable structured agent example: `examples/callback_basic/agent_run.py`.

#### Attack technique taxonomy & resistance profiling
- 31 attack techniques defined in `taxonomies/attack_techniques.py` (direct override, role-play, authority claim, encoding bypass, many-shot, RAG poisoning, XPIA, sycophancy, tool abuse, etc.).
- Every probe tagged with applicable techniques via `taxonomies/probe_technique_map.py`.
- Every `TestResult` carries `evidence["attack_techniques"]` for downstream analysis.
- `compute_resistance_profile()` aggregates pass/fail rates by technique after a run.
- Terminal report shows a "Resistance Profile" table with per-technique pass rates, visual bars, overall grade (Excellent/Good/Fair/Poor/Critical), and "prioritize defenses for" recommendation.
- Per-seed technique tagging for mixed-technique probes (`instruction_hierarchy`, `linguistic_evasion`, `refusal_bypass`, `sycophancy`) — avoids inflating technique counts.
- Turns a test report into an actionable defense roadmap: not just "N probes failed" but "your model is weakest against authority claims and encoding bypass."

#### Fail-safe inconclusive handling
- LLM judge failures now produce FAIL (not silent PASS) with `inconclusive` evidence markers.
- Runner, terminal reporter, and CLI all surface inconclusive counts with yellow warnings.
- LLM generators warn loudly when API keys are missing instead of silently falling back.

#### OWASP LLM Top 10 (2025) compliance
- Updated taxonomy from OWASP LLM Top 10 v1.0 (2023) to v2.0 (2025).
- All 27 probes mapped to OWASP categories (8/10 covered, 2 gaps with recommendations).
- `aegisrt run --compliance` flag for inline OWASP compliance summary after runs.
- `probe_to_owasp_categories()` reverse index — every `TestResult` carries `owasp_llm_top10` tags.
- Coverage gap analysis with actionable recommendations.

#### New probes (17 → 27)
- `encoding_attack` (25 seeds) — base64, hex, ROT13, unicode homoglyphs, leetspeak, reversed text, and mixed-encoding bypass.
- `instruction_hierarchy` (22 seeds) — system prompt priority vs authority claims, formatting injection, temporal arguments, nested override.
- `sycophancy` (20 seeds) — false premise agreement, expert pressure, social pressure, fabricated citations, emotional manipulation.
- `harmful_content` (25 seeds) — violence, fraud, self-harm, illegal activity, harassment, dangerous challenges with indirect framing.
- `unsafe_code` (20 seeds) — SQL injection, XSS, command injection, path traversal, hardcoded secrets, insecure deserialization in generated code.
- `many_shot_jailbreak` (15 seeds) — Anthropic-documented many-shot attack: context stuffing with fake compliance examples.
- `context_leakage` (18 seeds) — RAG document leakage, conversation history bleed, retrieved passage probing, metadata exposure.
- `linguistic_evasion` (20 seeds) — hypothetical framing, academic distancing, historical framing, euphemisms, continuation attacks.
- `semantic_injection` (18 seeds) — indirect/cross-prompt injection (XPIA) via emails, code, documents, CSV/JSON the model processes.
- `resource_exhaustion` (25 seeds) — unbounded consumption (OWASP LLM10): excessive repetition, unbounded generation, recursive patterns, computational DoS.

#### Seed corpus expansion
- `agent_tool_abuse`: 10 → 30 seeds (filesystem, browser, DB, admin, email, code exec, credentials, webhooks).
- `agent_cross_tenant`: 10 → 31 seeds (retrieval, memory, billing, injection bypass, handoff escalation, cross-user leakage).
- `rag_manipulation`: 16 → 25 seeds (credential injection, canary extraction, multi-document attacks).
- `output_policy`: 17 → 25 seeds (deepfake, impersonation, toxicity categories).
- `resource_exhaustion`: 15 → 25 seeds (additional repetition, unbounded, recursive, computational, token-wasting seeds).
- Total seed corpus: 370 → 636.

### Changed

- `TargetResponse.raw` type widened from `dict | str | None` to `Any` for agent response payloads.
- `TargetResponse.metadata` type annotation tightened to `dict[str, Any]`.
- `ScoreEvaluator` now filters inconclusive detections from aggregation and fails safe when all detections are inconclusive.

### Notes

- The new agent-native probes are complementary to existing prompt/response probes: they score structured execution traces rather than reusing text-only prompt heuristics.
- OWASP LLM03 (Supply Chain) and LLM04 (Data Poisoning) remain uncovered — both are infrastructure/governance concerns that cannot be tested by sending prompts.
- `rt_cbrn` is intentionally unmapped from OWASP — no honest category fit for CBRN content safety testing.
