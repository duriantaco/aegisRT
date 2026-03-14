# AegisRT vs Garak

Garak (by NVIDIA) is a research-oriented LLM vulnerability scanner inspired by nmap/Metasploit. AegisRT is a developer-focused security testing framework designed for CI/CD integration and workflow automation.

## Feature Comparison

| Dimension | AegisRT | Garak |
|---|---|---|
| Focus | Defense audit + red team | Red team / attack generation |
| Probe corpus | 118 seeds across 15 probes | 3,000+ prompt templates |
| Static code audit | Yes (8 AST rules) | No |
| Config complexity | 6 lines to start | 10+ lines |
| Report formats | 5 (terminal, JSON, HTML, SARIF, JUnit) | Terminal, JSON |
| Web dashboard | Yes | No |
| CI/CD integration | SARIF + JUnit (native) | Manual |
| Python callback target | Yes | No |
| LLM-as-judge | Yes | No |
| Prompt converters | 29 composable transforms | -- |
| Adaptive red teaming | LLM-vs-LLM + genetic mutation | -- |
| AIMD concurrency | Yes | No |
| Multi-model benchmarking | Yes | No |
| Plugin system | Python entry points | Python entry points |
| Built-in datasets | 5 JSONL datasets | Extensive built-in |

## When to choose AegisRT

- You need to integrate security testing into your **CI/CD pipeline** with SARIF and JUnit output
- You want a **web dashboard** to browse run history and triage findings
- You need **static code audit** alongside runtime testing
- You want **LLM-as-judge evaluation** for accurate compliance grading (not just keyword matching)
- You need to test a **Python function** directly without setting up an HTTP endpoint
- You want **multi-model benchmarking** to compare robustness across providers

## When to choose Garak

- You need the **broadest possible probe corpus** (3,000+ templates vs 118 seeds)
- You're doing **security research** and want the nmap/Metasploit mental model
- You need Garak's specific probe categories or generator types
