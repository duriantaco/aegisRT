# AegisRT Configuration Schema

## Overview

AegisRT uses YAML configuration files to define evaluation runs. The configuration is validated at load time using Pydantic models, which provide strict typing, default values, and clear error messages for invalid configurations.

---

## Full Annotated Example

```yaml
# ──────────────────────────────────────────────
# Target: the system under test
# ──────────────────────────────────────────────
target:
  # Target type. One of: callback, http, openai_compat, fastapi, subprocess
  type: openai_compat

  # URL for HTTP and OpenAI-compatible targets.
  # For openai_compat: auto-detects Anthropic vs OpenAI from URL.
  url: "https://api.anthropic.com/v1/messages"

  # HTTP headers. Supports ${ENV_VAR} expansion.
  headers:
    x-api-key: "${ANTHROPIC_API_KEY}"
    anthropic-version: "2023-06-01"

  # Target-specific parameters (model, temperature, etc.).
  params:
    model: claude-sonnet-4-20250514
    max_tokens: "256"
    temperature: "0"

  # Per-request timeout in seconds.
  timeout_seconds: 60

  # Retry count on transient failure.
  retries: 2

# ──────────────────────────────────────────────
# Runtime: execution parameters
# ──────────────────────────────────────────────
runtime:
  # Starting concurrency (AIMD will adapt dynamically).
  concurrency: 4

  # Minimum inter-request delay (enforced by AIMD scheduler).
  rate_limit_per_minute: 60

  # Number of retry attempts per case on transient failure.
  retries: 2

  # Per-request timeout in seconds.
  timeout_seconds: 30

  # Exponential backoff settings for retries.
  retry_backoff_base: 1.0
  retry_backoff_max: 60.0

  # Budget guard: maximum spend before aborting (0 = unlimited).
  max_cost_usd: 5.0

  # Checkpoint interval for resumable runs.
  checkpoint_every: 100

  # Resume from a previous checkpoint.
  # resume_from: "run_abc123"

  # Response cache settings.
  cache:
    enabled: true
    ttl_seconds: 3600
    max_size_mb: 100

# ──────────────────────────────────────────────
# Providers: LLM services used by the tool itself
# ──────────────────────────────────────────────
providers:
  # Attacker model used for LLM-based and adaptive test case generation.
  attacker:
    type: anthropic
    model: claude-haiku-4-5-20251001
    api_key: "${ANTHROPIC_API_KEY}"
    base_url: "https://api.anthropic.com/v1"

  # Judge model for LLM-as-judge evaluation (promptfoo-style).
  # When configured, replaces regex/keyword detectors with semantic grading.
  judge:
    type: anthropic
    model: claude-haiku-4-5-20251001
    api_key: "${ANTHROPIC_API_KEY}"
    base_url: "https://api.anthropic.com/v1"
    params:
      temperature: 0
      max_tokens: 256

# ──────────────────────────────────────────────
# Converters: prompt transforms (PyRIT-inspired)
# ──────────────────────────────────────────────
# Global converters applied to all probes.
# Per-probe converters (see probes section) override this.
converters:
  # Chain of converter IDs, applied left-to-right.
  chain:
    - base64
    - sandwich
  # Whether to keep original (unconverted) cases alongside converted ones.
  keep_originals: true

# ──────────────────────────────────────────────
# Probes: security tests to run
# ──────────────────────────────────────────────
probes:
  - id: prompt_injection
    family: injection
    enabled: true
    # Generator: static, mutation, llm, rag, template, dataset,
    #            conversation, adaptive, genetic
    generator: static
    # Detectors: regex, policy, leakage, json_schema, llm_judge
    detectors:
      - llm_judge
    severity: high
    # Per-probe converters (override global converters).
    converters:
      chain:
        - translation
        - suffix
      keep_originals: true

  - id: data_leakage
    family: privacy
    enabled: true
    generator: mutation
    detectors:
      - leakage
      - policy
    severity: critical

  - id: tool_misuse
    family: safety
    enabled: true
    generator: static
    detectors:
      - llm_judge
    severity: high

# ──────────────────────────────────────────────
# Report: output configuration
# ──────────────────────────────────────────────
report:
  formats:
    - terminal
    - json
    - html
    - sarif
    - junit
    - csv
  output_dir: ".aegisrt"
  fail_on:
    severity: high
    min_confidence: 0.7
```

---

## Section Reference

### `version`

**Type:** `int`
**Required:** Yes

Schema version number. Currently must be `1`. Used for forward-compatible config evolution.

### `target`

Defines the system under test.

| Field           | Type         | Default  | Description                                                    |
|-----------------|--------------|----------|----------------------------------------------------------------|
| `type`          | `string`     | required | One of `callback`, `http`, `openai_compat`, `fastapi`, `subprocess` |
| `url`           | `string`     | `null`   | Endpoint URL (required for `http` and `openai_compat`)         |
| `method`        | `string`     | `"POST"` | HTTP method                                                    |
| `headers`       | `dict`       | `{}`     | HTTP headers, supports env var expansion                       |
| `body_template` | `dict`       | `null`   | Request body with `{{prompt}}` placeholder                     |
| `response_path` | `string`     | `null`   | JSONPath to extract response text from JSON body               |
| `timeout_seconds` | `int`      | `30`     | Per-request timeout                                            |
| `retries`       | `int`        | `1`      | Retry count on transient failure                               |
| `params`        | `dict`       | `{}`     | Additional target-specific parameters                          |

For `callback` targets, use `params.module` and `params.function` to specify the Python callable, or set the callback programmatically via the Python API.

For `subprocess` targets, use `params.command` to specify the command to execute.

### `runtime`

Controls execution behavior. Concurrency is adaptive via AIMD scheduling.

| Field                    | Type    | Default      | Description                                         |
|--------------------------|---------|--------------|-----------------------------------------------------|
| `concurrency`            | `int`   | `4`          | Starting/max parallel case executions (AIMD adapts) |
| `rate_limit_per_minute`  | `int`   | `0`          | Min inter-request delay (0 = unlimited)             |
| `retries`                | `int`   | `1`          | Retry count per case                                |
| `timeout_seconds`        | `int`   | `30`         | Per-case timeout                                    |
| `retry_backoff_base`     | `float` | `1.0`        | Base delay for exponential backoff (seconds)        |
| `retry_backoff_max`      | `float` | `60.0`       | Maximum backoff delay (seconds)                     |
| `max_cost_usd`           | `float` | `0.0`        | Budget guard, abort if exceeded (0 = unlimited)     |
| `checkpoint_every`       | `int`   | `100`        | Save checkpoint every N cases                       |
| `resume_from`            | `string`| `null`       | Resume from a previous checkpoint run ID            |
| `cache`                  | `object`| see below    | Response caching settings                           |

#### `runtime.cache`

| Field          | Type   | Default | Description                          |
|----------------|--------|---------|--------------------------------------|
| `enabled`      | `bool` | `true`  | Enable response caching              |
| `ttl_seconds`  | `int`  | `3600`  | Cache entry time-to-live             |
| `max_size_mb`  | `int`  | `100`   | Maximum cache size on disk           |

### `providers`

LLM services used by AegisRT itself (not the target). These are optional and only needed when using LLM-based generators or the LLM judge detector.

Each provider block supports:

| Field      | Type     | Default  | Description                          |
|------------|----------|----------|--------------------------------------|
| `type`     | `string` | required | Provider type (`openai_compat`, `anthropic`) |
| `model`    | `string` | required | Model identifier                     |
| `api_key`  | `string` | `null`   | API key, supports env var expansion  |
| `base_url` | `string` | `null`   | Base URL for compatible APIs         |

### `converters`

Prompt converter pipeline configuration. Can be set globally (top-level) or per-probe. Per-probe settings override global.

| Field           | Type        | Default | Description                                        |
|-----------------|-------------|---------|----------------------------------------------------|
| `chain`         | `list[str]` | `[]`    | Converter IDs applied left-to-right                |
| `keep_originals`| `bool`      | `true`  | Include original cases alongside converted ones    |

Converter IDs can include parameters: `"caesar:shift=5"`, `"translation:target_language=French"`.

Available converters (29):

| Category | IDs |
|---|---|
| Encoding | `base64`, `rot13`, `hex`, `caesar`, `url_encode`, `morse` |
| Evasion | `homoglyph`, `unicode_confusable`, `zero_width`, `whitespace`, `case_swap`, `reverse`, `char_spacing` |
| Linguistic | `leetspeak`, `pig_latin`, `translation`, `rephrase`, `word_substitution`, `acronym` |
| Injection | `sandwich`, `suffix`, `few_shot`, `role_prefix`, `instruction_tag`, `markdown_wrap`, `payload_split`, `fictional`, `research` |

### `probes`

A list of security test configurations. Each probe binds together a generator (how to create inputs), detectors (how to evaluate outputs), and metadata (severity, tags).

| Field        | Type         | Default    | Description                              |
|--------------|--------------|------------|------------------------------------------|
| `id`         | `string`     | required   | Probe identifier for this run/report     |
| `extends`    | `string`     | `null`     | Reuse a built-in/plugin probe definition |
| `family`     | `string`     | inherited  | Probe family for grouping                |
| `enabled`    | `bool`       | `true`     | Whether to include this probe in the run |
| `generator`  | `string`     | inherited  | Generator name: `static`, `mutation`, `llm`, `rag`, `template`, `dataset`, `conversation`, `adaptive`, `genetic` |
| `detectors`  | `list[str]`  | inherited  | Detector names to apply                  |
| `severity`   | `string`     | inherited  | One of `low`, `medium`, `high`, `critical` |
| `generator_config` | `object` | `null`   | Generator-specific settings such as inline prompts, dataset paths, or template variables |
| `converters` | `object`     | `null`     | Per-probe converter config (overrides global) |

### `probes[].generator_config`

Use this block when you want to supply your own prompt inputs without writing a plugin.

Recommended usage:

- Use `generator: dataset` with a JSONL file for most real runs.
- Use `prompts` inline only for a few quick tests.
- Use `template` only when you want one prompt pattern expanded across variables.
- Use `extends` to keep the built-in probe's detectors/remediation while replacing the prompt source.

| Field        | Type                | Default  | Description |
|--------------|---------------------|----------|-------------|
| `prompts`    | `list[str]`         | `[]`     | Inline prompts for `static` or `template` generators |
| `path`       | `string`            | `null`   | Dataset path for the `dataset` generator |
| `format`     | `string`            | `"auto"` | Dataset format: `auto`, `csv`, `json`, `jsonl` |
| `column_map` | `dict[str, string]` | `{}`     | Map dataset columns onto canonical fields such as `prompt` |
| `variables`  | `dict[str, list]`   | `{}`     | Variable expansions for the `template` generator |

### `report`

Report generation settings.

| Field       | Type        | Default                | Description                    |
|-------------|-------------|------------------------|--------------------------------|
| `formats`   | `list[str]` | `["terminal", "json"]` | Output formats to generate     |
| `output_dir`| `string`    | `".aegisrt"`           | Report output directory        |
| `fail_on`   | `object`    | see below              | CI failure threshold           |

#### `report.fail_on`

| Field            | Type    | Default    | Description                              |
|------------------|---------|------------|------------------------------------------|
| `severity`       | `string`| `"high"`   | Min severity to trigger CI failure       |
| `min_confidence` | `float` | `0.7`      | Min confidence for a finding to count    |

---

## Environment Variable Expansion

AegisRT supports `${ENV_VAR}` syntax anywhere in string values. Variables are expanded at config load time before Pydantic validation.

```yaml
headers:
  Authorization: "Bearer ${API_TOKEN}"

providers:
  attacker:
    api_key: "${OPENAI_API_KEY}"
```

If a referenced variable is not set, AegisRT raises a clear error at load time identifying which variable is missing and which config field references it.

Expansion rules:
- `${VAR}` -- expands to the value of environment variable `VAR`
- `${VAR:-default}` -- expands to `VAR` if set, otherwise uses `default`
- Expansion is recursive: a default value cannot contain further `${}` references
- Expansion applies to string values only; it does not apply to keys, integers, or booleans

---

## Pydantic Validation

The config is validated using a hierarchy of Pydantic `BaseModel` classes:

```text
RunConfig
  +-- TargetConfig
  +-- RuntimeConfig
  |     +-- CacheConfig
  +-- ProvidersConfig
  |     +-- ProviderConfig (attacker)
  |     +-- ProviderConfig (judge)
  +-- ConverterConfig
  +-- list[ProbeConfig]
  |     +-- ConverterConfig (per-probe override)
  +-- ReportConfig
        +-- FailPolicy

BenchmarkConfig
  +-- list[BenchmarkTargetConfig]
  +-- RuntimeConfig
  +-- ProvidersConfig
  +-- ConverterConfig
  +-- list[ProbeConfig]
  +-- ReportConfig
```

Validation covers:
- Required fields are present
- Enum values are valid (target type, severity, generator name)
- Types are correct (integers, booleans, strings, lists)
- Cross-field consistency (e.g., `url` is required when `type` is `http`)
- Probe IDs are unique within a config
- Referenced detectors and generators exist

Validation errors are formatted as human-readable messages with the config path of the invalid field, the expected type or value, and what was actually provided.
