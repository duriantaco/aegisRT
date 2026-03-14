# AegisRT vs DeepTeam

DeepTeam (by Confident AI) is a Python API for LLM red teaming. AegisRT is a full-stack security testing framework with CLI, YAML config, web dashboard, and CI/CD output formats.

## Feature Comparison

| Dimension | AegisRT | DeepTeam |
|---|---|---|
| Interface | CLI + Python API + Web dashboard | Python API only |
| Configuration | YAML file (declarative) | Code-only (imperative) |
| Static code audit | Yes (8 AST rules) | No |
| Report formats | 5 (terminal, JSON, HTML, SARIF, JUnit) | Limited |
| Target types | 5 (callback, HTTP, OpenAI, FastAPI, subprocess) | Code-only |
| LLM-as-judge | Yes | Yes |
| Prompt converters | 29 composable transforms | -- |
| Adaptive red teaming | LLM-vs-LLM + genetic mutation | Yes |
| Multi-model benchmarking | Yes | No |
| Plugin system | Python entry points | No |
| OWASP LLM Top 10 | 7/10 mapped | Partial |
| Built-in datasets | 5 JSONL datasets | -- |
| Web dashboard | Yes | Via DeepEval platform |
| CI/CD integration | SARIF + JUnit | Manual |

## When to choose AegisRT

- You want **declarative YAML config** instead of writing boilerplate Python for each test scenario
- You need **CI/CD integration** with SARIF (GitHub Code Scanning) and JUnit output
- You want a **self-hosted web dashboard** for browsing results without a third-party platform
- You need **static code audit** to catch LLM anti-patterns in your source
- You want to test **multiple target types** (HTTP endpoints, Anthropic/OpenAI APIs, Python callbacks, subprocesses)
- You want **prompt converters** for attack surface multiplication

## When to choose DeepTeam

- You prefer writing tests entirely in Python code (no YAML)
- You're already using DeepEval for general LLM evaluation and want red teaming in the same ecosystem
- You need DeepTeam's specific attack strategies
