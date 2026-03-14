# AegisRT vs Promptfoo

Promptfoo is a popular JavaScript/TypeScript LLM evaluation framework (now part of OpenAI). AegisRT is a Python-native alternative purpose-built for security testing.

## Feature Comparison

| Dimension | AegisRT | Promptfoo |
|---|---|---|
| Language | Python-native | JavaScript/TypeScript |
| Config format | YAML + Python API | YAML |
| Static code audit | Yes (8 AST-based rules) | No |
| Python callback target | First-class (`callback_fn`) | Requires wrapper/adapter |
| SARIF output | Yes (GitHub Code Scanning) | No |
| JUnit output | Yes (CI gating) | Yes |
| pytest integration | Built-in | No |
| Prompt converters | 29 composable transforms | -- |
| Adaptive red teaming | LLM-vs-LLM + genetic mutation | No |
| LLM-as-judge | Yes | Yes |
| AIMD concurrency | Yes | Yes |
| Web dashboard | Yes | Yes |
| Multi-model benchmarking | Yes | Yes (eval grid) |
| Built-in datasets | 5 JSONL datasets | -- |
| Plugin system | Python entry points | Yes |
| Ecosystem | PyPI / Python toolchain | npm / Node toolchain |
| OWASP LLM Top 10 | 7/10 covered | Varies by config |

## When to choose AegisRT

- Your LLM application is written in **Python** and you want native integration without leaving the Python ecosystem
- You need to **test a Python function directly** as a callback -- no HTTP server required
- You need **SARIF output** for GitHub Code Scanning integration
- You want **static code audit** to catch LLM anti-patterns in your source (hardcoded secrets, `exec()` on model output, unsanitized RAG injection)
- You want **pytest integration** to embed security assertions in your existing test suite
- You need **prompt converters** to multiply your attack surface (Base64, homoglyphs, sandwich attacks, etc.)

## When to choose Promptfoo

- Your stack is JavaScript/TypeScript and you prefer staying in the Node ecosystem
- You need Promptfoo's eval comparison grid for non-security LLM evaluation
- You're already invested in Promptfoo's configuration format and plugin ecosystem
