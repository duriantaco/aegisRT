# AegisRT Architecture

## Overview

AegisRT is a Python-native LLM security testing and defense-audit framework. It combines runtime adversarial evaluation with static code-aware defense validation, providing a unified tool for securing LLM-powered applications.

The architecture draws its external UX from Promptfoo's config-driven, CI-friendly model, while using garak's clean plugin and pipeline internals for extensibility.

---

## Two Operating Modes

### Mode A: Runtime Security Evaluation

Answers the question: **Can this LLM system be made to fail under adversarial conditions?**

This mode sends crafted inputs to a live target (callback function, HTTP endpoint, OpenAI-compatible server, etc.), captures responses, runs detectors against those responses, and produces scored findings with remediation guidance.

Use cases:
- Prompt injection resistance testing
- Data leakage detection
- Tool misuse boundary validation
- Refusal bypass probing
- RAG context trust verification

### Mode B: Static Defense Audit

Answers the question: **Did the developer forget important defenses in the codebase?**

This mode uses Python AST analysis to scan source code for common LLM integration anti-patterns, such as unsafe prompt construction, missing output validation, unrestricted tool exposure, and secrets flowing into prompts.

Use cases:
- Pre-deployment defense checklist enforcement
- Code review augmentation
- CI gating on defense coverage
- Identifying missing guardrails before runtime testing

---

## Ten Architecture Layers

### Layer 1: Config

Responsible for loading YAML configuration, validating it with Pydantic models, expanding environment variables, and normalizing run settings into a typed `RunConfig` object. Supports both single-target `RunConfig` and multi-target `BenchmarkConfig`.

Key modules: `config/models.py`, `config/loader.py`, `config/schema.py`

### Layer 2: Target

Represents the system under test. Provides a uniform `execute(prompt) -> TargetResponse` interface regardless of whether the target is a Python callback, an HTTP API, an OpenAI-compatible endpoint (auto-detects Anthropic vs OpenAI from URL), a FastAPI app, or a subprocess.

Key modules: `targets/base.py`, `targets/callback.py`, `targets/http.py`, `targets/openai_compat.py`, `targets/fastapi_target.py`, `targets/subprocess_target.py`

### Layer 3: Generator

Produces test cases for probes. Nine generator types:

- **Static** -- fixed seed templates, 1:1 mapping
- **Mutation** -- 15 character-level transforms applied to seeds
- **LLM** -- attacker model synthesizes adversarial prompts
- **RAG** -- builds tests around retrieval context structure
- **Template** -- Cartesian product expansion of template variables
- **Dataset** -- loads cases from CSV/JSON/JSONL files or `builtin://` URIs
- **Conversation** -- multi-turn attack scenarios
- **Adaptive** -- LLM-vs-LLM feedback loop that evolves attacks over iterations
- **Genetic** -- non-LLM evolutionary mutation of prompts

Key modules: `generators/base.py`, `generators/static.py`, `generators/mutations.py`, `generators/llm.py`, `generators/rag.py`, `generators/template.py`, `generators/dataset.py`, `generators/conversation.py`, `generators/adaptive.py`, `generators/genetic.py`

### Layer 3.5: Converter Pipeline

Composable text transforms applied to test cases **after** generation and **before** execution. Unlike generators (which are tightly coupled to probes), converters work as a separate pipeline layer that applies to ANY probe's cases. Converters can be chained (e.g., translate -> Base64 -> sandwich) and configured globally or per-probe in YAML.

29 built-in converters across four categories:
- **Encoding** (6): `base64`, `rot13`, `hex`, `caesar`, `url_encode`, `morse`
- **Evasion** (7): `homoglyph`, `unicode_confusable`, `zero_width`, `whitespace`, `case_swap`, `reverse`, `char_spacing`
- **Linguistic** (6): `leetspeak`, `pig_latin`, `translation`, `rephrase`, `word_substitution`, `acronym`
- **Injection/Framing** (10): `sandwich`, `suffix`, `few_shot`, `role_prefix`, `instruction_tag`, `markdown_wrap`, `payload_split`, `fictional`, `research`

Key modules: `converters/base.py`, `converters/encoding.py`, `converters/evasion.py`, `converters/linguistic.py`, `converters/injection.py`, `converters/registry.py`

### Layer 4: Harness (embedded in core/runner)

Orchestrates test execution: sending cases to targets, applying converter pipelines, managing retries, enforcing timeouts, controlling concurrency via AIMD scheduling, logging interactions, and capturing artifacts. Uses `run_with_aimd()` for adaptive concurrency that halves on rate limits (429s) and slowly recovers.

Key modules: `core/runner.py`, `core/session.py`, `core/benchmark.py`, `core/batch_runner.py`, `utils/aimd_scheduler.py`

### Layer 5: Detector

Analyzes target responses for policy failures. Detectors are layered: deterministic checks (regex, forbidden strings, schema violations) run first; contextual checks (policy rules, boundary logic) run second; LLM-as-judge evaluation runs last.

When a `providers.judge` is configured, the **LLM judge** becomes the primary detector. It evaluates whether the target **actually complied** with harmful intent (promptfoo-style grading), not just whether keywords appeared. Supports both OpenAI and Anthropic APIs with automatic retry and exponential backoff on rate limits.

Key modules: `detectors/base.py`, `detectors/regex.py`, `detectors/policy.py`, `detectors/json_schema.py`, `detectors/llm_judge.py`, `detectors/leakage.py`

### Layer 6: Evaluator

Combines detector outputs into final verdicts. Assigns pass/fail status, severity, confidence scores, aggregated evidence, and remediation guidance. Includes a `RobustnessEvaluator` with Wilson score confidence intervals for statistical rigor.

Key modules: `evaluators/base.py`, `evaluators/score.py`, `evaluators/confidence.py`, `evaluators/remediation.py`, `evaluators/robustness.py`

### Layer 7: Reporting

Renders evaluation results into multiple output formats: rich terminal tables, structured JSON, SARIF (for GitHub Code Scanning), HTML dashboards, JUnit XML (for CI test runners), and CSV. Benchmark reports include robustness matrices, ranking tables, and radar charts.

Key modules: `reports/terminal.py`, `reports/json_report.py`, `reports/html_report.py`, `reports/sarif_report.py`, `reports/junit_report.py`, `reports/csv_report.py`, `reports/benchmark_report.py`

### Layer 8: Code Audit

Scans Python source files using AST traversal. Identifies LLM integration callsites, detects unsafe patterns (prompt concatenation with user input, missing output validation, unrestricted tool exposure), and produces audit findings with rule IDs, severity levels, and remediation text.

Key modules: `audit/discover.py`, `audit/python_ast.py`, `audit/rules.py`, `audit/findings.py`

---

## Execution Flow

### Runtime Evaluation (Mode A)

```text
                         +------------------+
                         |   Load Config    |
                         |  (YAML + env)    |
                         +--------+---------+
                                  |
                         +--------v---------+
                         |  Resolve Target  |
                         | (callback/http/  |
                         |  openai/fastapi) |
                         +--------+---------+
                                  |
                         +--------v---------+
                         | Load Enabled     |
                         | Probes + Plugins |
                         +--------+---------+
                                  |
                    +-------------v--------------+
                    |  For each probe:           |
                    |    Generator -> TestCases  |
                    +-------------+--------------+
                                  |
                    +-------------v--------------+
                    |  Apply Converter Pipeline  |
                    |  (if configured)           |
                    +-------------+--------------+
                                  |
                    +-------------v--------------+
                    |  For each case (AIMD):     |
                    |    Target.execute(prompt)   |
                    +-------------+--------------+
                                  |
                    +-------------v--------------+
                    |  For each case+response:   |
                    |    Run all detectors       |
                    +-------------+--------------+
                                  |
                    +-------------v--------------+
                    |  Evaluator: aggregate      |
                    |  scores, severity,         |
                    |  confidence, remediation   |
                    +-------------+--------------+
                                  |
                         +--------v---------+
                         |  Store Findings  |
                         |  (SQLite/JSON)   |
                         +--------+---------+
                                  |
                         +--------v---------+
                         | Generate Reports |
                         | (term/json/html/ |
                         |  sarif/junit)    |
                         +--------+---------+
                                  |
                         +--------v---------+
                         | Apply Fail       |
                         | Thresholds       |
                         +--------+---------+
                                  |
                         +--------v---------+
                         | Return CI Exit   |
                         | Code (0 or 1)    |
                         +------------------+
```

### Static Audit (Mode B)

```text
    +------------------+
    | Scan source tree |
    | (*.py files)     |
    +--------+---------+
             |
    +--------v---------+
    | Parse AST per    |
    | file             |
    +--------+---------+
             |
    +--------v---------+
    | Run audit rules  |
    | against AST      |
    +--------+---------+
             |
    +--------v---------+
    | Collect findings |
    | with rule IDs    |
    +--------+---------+
             |
    +--------v---------+
    | Generate report  |
    | (term/json/sarif)|
    +------------------+
```

---

## Plugin Model

AegisRT uses Python entry points for plugin extensibility. Third-party packages can register custom probes, detectors, generators, and converters by declaring entry points in their `pyproject.toml`.

### Entry Point Groups

| Group                  | Purpose                              |
|------------------------|--------------------------------------|
| `aegisrt.probes`       | Custom probe classes                 |
| `aegisrt.detectors`    | Custom detector classes              |
| `aegisrt.generators`   | Custom generator classes             |
| `aegisrt.converters`   | Custom converter classes             |

### Plugin Loading

At startup, AegisRT discovers all installed entry points in each group using `importlib.metadata.entry_points()`. Plugins are loaded lazily -- only instantiated when referenced by a probe configuration. This keeps startup fast and avoids importing unused dependencies.

### Registration

A plugin package registers itself in `pyproject.toml`:

```toml
[project.entry-points."aegisrt.probes"]
my_custom_probe = "my_plugin.probes:MyCustomProbe"
```

Once installed, the probe becomes available by name (`my_custom_probe`) in AegisRT configuration files and CLI output.

---

## Data Flow Summary

All data flows through Pydantic models:

- `RunConfig` -- validated configuration
- `TestCase` -- a single input to send to the target
- `TargetResponse` -- the raw and processed response from the target
- `Detection` -- a single detector's finding for one case
- `TestResult` -- the aggregated evaluation of one case
- `Report` -- the full collection of results with metadata

This ensures type safety, serialization, and validation at every boundary.

---

## Storage

Run artifacts (configs, inputs, outputs, results, reports) are stored in a local `.aegisrt/` directory by default. An optional SQLite backend supports querying historical runs, replaying test cases, and comparing results across runs.

---

## Concurrency

The runner uses an **AIMD (Additive Increase, Multiplicative Decrease) scheduler** for adaptive concurrency. Starting at the configured `runtime.concurrency`, the scheduler:

- **Halves concurrency** on rate limit (HTTP 429) responses
- **Increases concurrency by 1** after 10 consecutive successes (up to the configured max)
- **Enforces minimum inter-request delay** based on `runtime.rate_limit_per_minute`
- **Retries rate-limited requests** with exponential backoff and Retry-After header support

This approach (used by promptfoo and other production LLM tools) prevents cascading failures under rate limiting while maximizing throughput when capacity is available.

Key modules: `utils/aimd_scheduler.py`, `utils/rate_limit.py`
