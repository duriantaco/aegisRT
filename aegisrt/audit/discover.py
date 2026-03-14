
from __future__ import annotations

import ast
from pathlib import Path

from pydantic import BaseModel, Field

from aegisrt.audit.python_ast import parse_file

class DiscoveryFinding(BaseModel):

    file_path: str
    integration_type: str
    module_name: str
    line: int
    recommended_probes: list[str] = Field(default_factory=list)
    recommended_rules: list[str] = Field(default_factory=list)

class DiscoveryReport(BaseModel):

    findings: list[DiscoveryFinding] = Field(default_factory=list)
    summary: dict = Field(default_factory=dict)

_LLM_MODULES: dict[str, dict] = {
    "openai": {
        "type": "llm",
        "probes": ["prompt-injection", "jailbreak", "system-prompt-leak"],
        "rules": ["AUD001", "AUD002", "AUD004", "AUD006", "AUD007"],
    },
    "anthropic": {
        "type": "llm",
        "probes": ["prompt-injection", "jailbreak", "system-prompt-leak"],
        "rules": ["AUD001", "AUD002", "AUD004", "AUD006", "AUD007"],
    },
    "google.generativeai": {
        "type": "llm",
        "probes": ["prompt-injection", "jailbreak"],
        "rules": ["AUD001", "AUD002", "AUD004", "AUD007"],
    },
    "cohere": {
        "type": "llm",
        "probes": ["prompt-injection", "jailbreak"],
        "rules": ["AUD001", "AUD002", "AUD004"],
    },
    "ollama": {
        "type": "llm",
        "probes": ["prompt-injection", "jailbreak"],
        "rules": ["AUD001", "AUD002"],
    },
    "litellm": {
        "type": "llm",
        "probes": ["prompt-injection", "jailbreak", "system-prompt-leak"],
        "rules": ["AUD001", "AUD002", "AUD004", "AUD006", "AUD007"],
    },
    "langchain": {
        "type": "framework",
        "probes": ["prompt-injection", "jailbreak", "tool-abuse"],
        "rules": ["AUD001", "AUD003", "AUD005", "AUD008"],
    },
    "llama_index": {
        "type": "framework",
        "probes": ["prompt-injection", "rag-poisoning"],
        "rules": ["AUD001", "AUD005"],
    },
    "crewai": {
        "type": "agent-framework",
        "probes": ["prompt-injection", "tool-abuse", "jailbreak"],
        "rules": ["AUD003", "AUD008"],
    },
    "autogen": {
        "type": "agent-framework",
        "probes": ["prompt-injection", "tool-abuse", "code-exec"],
        "rules": ["AUD003", "AUD008"],
    },
    "semantic_kernel": {
        "type": "framework",
        "probes": ["prompt-injection", "tool-abuse"],
        "rules": ["AUD001", "AUD003"],
    },
}

_VECTORDB_MODULES: dict[str, dict] = {
    "chromadb": {
        "type": "vectordb",
        "probes": ["rag-poisoning"],
        "rules": ["AUD005"],
    },
    "pinecone": {
        "type": "vectordb",
        "probes": ["rag-poisoning"],
        "rules": ["AUD005"],
    },
    "weaviate": {
        "type": "vectordb",
        "probes": ["rag-poisoning"],
        "rules": ["AUD005"],
    },
    "qdrant_client": {
        "type": "vectordb",
        "probes": ["rag-poisoning"],
        "rules": ["AUD005"],
    },
    "pymilvus": {
        "type": "vectordb",
        "probes": ["rag-poisoning"],
        "rules": ["AUD005"],
    },
}

_ALL_MODULES = {**_LLM_MODULES, **_VECTORDB_MODULES}

class DiscoveryScanner:

    def scan(self, root_path: str | Path) -> DiscoveryReport:
        root = Path(root_path)
        findings: list[DiscoveryFinding] = []
        scanned = 0

        py_files = sorted(root.rglob("*.py"))
        for py_file in py_files:
            parts = py_file.parts
            if any(p.startswith(".") or p in {"__pycache__", "node_modules"} for p in parts):
                continue

            tree = parse_file(py_file)
            if tree is None:
                continue
            scanned += 1
            findings.extend(self._scan_file(tree, str(py_file)))

        summary = self._build_summary(findings, scanned)
        return DiscoveryReport(findings=findings, summary=summary)

    def _scan_file(self, tree: ast.Module, file_path: str) -> list[DiscoveryFinding]:
        findings: list[DiscoveryFinding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    info = self._match_module(alias.name)
                    if info:
                        findings.append(
                            DiscoveryFinding(
                                file_path=file_path,
                                integration_type=info["type"],
                                module_name=alias.name,
                                line=getattr(node, "lineno", 0),
                                recommended_probes=info["probes"],
                                recommended_rules=info["rules"],
                            )
                        )
            elif isinstance(node, ast.ImportFrom) and node.module:
                info = self._match_module(node.module)
                if info:
                    findings.append(
                        DiscoveryFinding(
                            file_path=file_path,
                            integration_type=info["type"],
                            module_name=node.module,
                            line=getattr(node, "lineno", 0),
                            recommended_probes=info["probes"],
                            recommended_rules=info["rules"],
                        )
                    )
        return findings

    @staticmethod
    def _match_module(module_name: str) -> dict | None:
        for known, info in _ALL_MODULES.items():
            if module_name == known or module_name.startswith(known + "."):
                return info
        return None

    @staticmethod
    def _build_summary(
        findings: list[DiscoveryFinding], scanned: int
    ) -> dict:
        integration_types: dict[str, int] = {}
        modules_found: set[str] = set()
        all_probes: set[str] = set()
        all_rules: set[str] = set()

        for f in findings:
            integration_types[f.integration_type] = (
                integration_types.get(f.integration_type, 0) + 1
            )
            modules_found.add(f.module_name)
            all_probes.update(f.recommended_probes)
            all_rules.update(f.recommended_rules)

        return {
            "scanned_files": scanned,
            "total_findings": len(findings),
            "integration_types": integration_types,
            "modules_found": sorted(modules_found),
            "recommended_probes": sorted(all_probes),
            "recommended_rules": sorted(all_rules),
        }
