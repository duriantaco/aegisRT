
from __future__ import annotations

import ast
import re
from abc import ABC, abstractmethod

from aegisrt.audit.findings import AuditFinding
from aegisrt.audit.python_ast import (
    extract_code_snippet,
    find_function_calls,
    find_string_concatenation,
    find_fstring_with_names,
)

class AuditRule(ABC):

    id: str
    description: str
    severity: str

    @abstractmethod
    def match(self, tree: ast.Module, file_path: str) -> list[AuditFinding]:
        pass

    def _finding(
        self, file_path: str, line: int, message: str, remediation: str
    ) -> AuditFinding:
        return AuditFinding(
            rule_id=self.id,
            file_path=file_path,
            line=line,
            message=message,
            severity=self.severity,
            remediation=remediation,
            code_snippet=extract_code_snippet(file_path, line),
        )

_LLM_CALL_NAMES: set[str] = {
    "create", "chat", "completions", "complete",
    "messages",
    "generate", "invoke", "run", "predict", "call",
    "completion", "acompletion",
}

_LLM_IMPORT_MODULES: set[str] = {
    "openai", "anthropic", "cohere", "google.generativeai",
    "litellm", "langchain", "llama_index", "ollama",
}

_USER_INPUT_NAMES: set[str] = {
    "user_input", "user_message", "user_query", "user_prompt",
    "query", "prompt", "question", "message", "input_text",
    "request", "user_text", "content",
}

def _has_llm_import(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if any(alias.name.startswith(mod) for mod in _LLM_IMPORT_MODULES):
                    return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and any(
                node.module.startswith(mod) for mod in _LLM_IMPORT_MODULES
            ):
                return True
    return False

def _collect_llm_call_lines(tree: ast.Module) -> set[int]:
    calls = find_function_calls(tree, _LLM_CALL_NAMES)
    return {c.lineno for c in calls if hasattr(c, "lineno")}

class PromptConcatenationRule(AuditRule):

    id = "AUD001"
    description = "Detects direct string concatenation or f-strings building prompts from user input"
    severity = "high"

    def match(self, tree: ast.Module, file_path: str) -> list[AuditFinding]:
        if not _has_llm_import(tree):
            return []
        findings: list[AuditFinding] = []

        fstrings = find_fstring_with_names(tree, _USER_INPUT_NAMES)
        for node in fstrings:
            findings.append(
                self._finding(
                    file_path,
                    getattr(node, "lineno", 0),
                    "F-string builds prompt from user-controlled variable; "
                    "risk of prompt injection.",
                    "Use parameterized prompt templates and validate/sanitize "
                    "user input before interpolation.",
                )
            )

        llm_lines = _collect_llm_call_lines(tree)
        concat_nodes = find_string_concatenation(tree)
        for node in concat_nodes:
            line = getattr(node, "lineno", 0)
            names_in_expr = _names_in_node(node)
            if names_in_expr & _USER_INPUT_NAMES:
                if not llm_lines or any(abs(line - ll) <= 15 for ll in llm_lines):
                    findings.append(
                        self._finding(
                            file_path,
                            line,
                            "String concatenation with user input near LLM call; "
                            "risk of prompt injection.",
                            "Use parameterized prompt templates instead of "
                            "string concatenation.",
                        )
                    )
        return findings

class NoOutputValidationRule(AuditRule):

    id = "AUD002"
    description = "Detects LLM API responses used without validation or parsing"
    severity = "medium"

    _VALIDATION_NAMES: set[str] = {
        "validate", "parse", "check", "sanitize", "clean",
        "json_loads", "loads", "parse_obj", "model_validate",
        "strip", "filter",
    }

    def match(self, tree: ast.Module, file_path: str) -> list[AuditFinding]:
        if not _has_llm_import(tree):
            return []
        findings: list[AuditFinding] = []
        llm_calls = find_function_calls(tree, _LLM_CALL_NAMES)

        for call_node in llm_calls:
            line = getattr(call_node, "lineno", 0)
            validation_calls = find_function_calls(tree, self._VALIDATION_NAMES)
            validation_lines = {
                getattr(v, "lineno", 0) for v in validation_calls
            }
            has_nearby_validation = any(
                0 < (vl - line) <= 10 for vl in validation_lines
            )
            if not has_nearby_validation:
                findings.append(
                    self._finding(
                        file_path,
                        line,
                        "LLM API response used without apparent validation "
                        "or parsing.",
                        "Validate and parse LLM outputs before using them "
                        "(e.g., JSON schema validation, content filtering).",
                    )
                )
        return findings

class ExposedToolsRule(AuditRule):

    id = "AUD003"
    description = "Detects tool/function registration without allowlists"
    severity = "high"

    _REGISTRATION_NAMES: set[str] = {
        "tool", "function_tool", "register_tool", "add_tool",
        "Tool", "StructuredTool", "FunctionTool",
        "register_function", "add_function",
    }

    _ALLOWLIST_PATTERNS: set[str] = {
        "allowed", "allowlist", "whitelist", "permitted",
        "approved", "safe_tools", "enabled_tools",
    }

    def match(self, tree: ast.Module, file_path: str) -> list[AuditFinding]:
        findings: list[AuditFinding] = []
        registrations = find_function_calls(tree, self._REGISTRATION_NAMES)
        if not registrations:
            return []

        all_names = {
            n.id for n in ast.walk(tree) if isinstance(n, ast.Name)
        }
        has_allowlist = bool(all_names & self._ALLOWLIST_PATTERNS)

        if not has_allowlist:
            for node in registrations:
                findings.append(
                    self._finding(
                        file_path,
                        getattr(node, "lineno", 0),
                        "Tool/function registration detected without an "
                        "explicit allowlist restricting available tools.",
                        "Maintain an explicit allowlist of permitted tools "
                        "and validate tool calls against it.",
                    )
                )
        return findings

_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}", re.I),
    re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}", re.I),
    re.compile(r"(?:secret|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}", re.I),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"bearer\s+[A-Za-z0-9_\-.]{20,}", re.I),
]

class HardcodedSecretsInPromptsRule(AuditRule):

    id = "AUD004"
    description = "Detects hardcoded API keys, passwords, or secrets in prompt strings"
    severity = "critical"

    def match(self, tree: ast.Module, file_path: str) -> list[AuditFinding]:
        findings: list[AuditFinding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for pat in _SECRET_PATTERNS:
                    if pat.search(node.value):
                        findings.append(
                            self._finding(
                                file_path,
                                getattr(node, "lineno", 0),
                                "Hardcoded secret detected in string literal "
                                "that may be used as a prompt.",
                                "Move secrets to environment variables or a "
                                "secrets manager; never embed them in code.",
                            )
                        )
                        break
        return findings

class UnsafeRetrievalInjectionRule(AuditRule):

    id = "AUD005"
    description = "Detects retrieval results directly inserted into prompts without sanitization"
    severity = "high"

    _RETRIEVAL_NAMES: set[str] = {
        "similarity_search", "query", "search", "retrieve",
        "get_relevant_documents", "as_retriever",
        "vector_search", "knn_search",
    }

    _SANITIZE_NAMES: set[str] = {
        "sanitize", "clean", "escape", "strip_tags", "bleach",
        "filter", "validate",
    }

    def match(self, tree: ast.Module, file_path: str) -> list[AuditFinding]:
        findings: list[AuditFinding] = []
        retrieval_calls = find_function_calls(tree, self._RETRIEVAL_NAMES)
        if not retrieval_calls:
            return []

        sanitize_calls = find_function_calls(tree, self._SANITIZE_NAMES)
        sanitize_lines = {getattr(s, "lineno", 0) for s in sanitize_calls}
        llm_lines = _collect_llm_call_lines(tree)

        for call_node in retrieval_calls:
            line = getattr(call_node, "lineno", 0)
            has_llm_after = any(ll > line for ll in llm_lines)
            has_sanitize_between = any(
                line < sl <= max(llm_lines, default=line) for sl in sanitize_lines
            )
            if has_llm_after and not has_sanitize_between:
                findings.append(
                    self._finding(
                        file_path,
                        line,
                        "Retrieval results appear to be inserted into prompts "
                        "without sanitization; risk of indirect prompt injection.",
                        "Sanitize and validate retrieval results before "
                        "inserting them into prompts.",
                    )
                )
        return findings

class MissingSystemMessageRule(AuditRule):

    id = "AUD006"
    description = "Detects chat completion calls without explicit system messages"
    severity = "medium"

    _CHAT_CALL_NAMES: set[str] = {"create", "messages", "chat", "completion"}

    def match(self, tree: ast.Module, file_path: str) -> list[AuditFinding]:
        if not _has_llm_import(tree):
            return []
        findings: list[AuditFinding] = []
        calls = find_function_calls(tree, self._CHAT_CALL_NAMES)

        for call_node in calls:
            messages_arg = None
            for kw in call_node.keywords:
                if kw.arg == "messages":
                    messages_arg = kw.value
                    break
            if messages_arg is None:
                continue

            has_system = self._has_system_role(messages_arg)
            if not has_system:
                findings.append(
                    self._finding(
                        file_path,
                        getattr(call_node, "lineno", 0),
                        "Chat completion call without a system message; "
                        "the model has no explicit behavioral constraints.",
                        "Always include a system message that defines the "
                        "model's role and behavioral boundaries.",
                    )
                )
        return findings

    @staticmethod
    def _has_system_role(node: ast.expr) -> bool:
        if not isinstance(node, ast.List):
            return True
        for elt in node.elts:
            if isinstance(elt, ast.Dict):
                for key, val in zip(elt.keys, elt.values):
                    if (
                        isinstance(key, ast.Constant)
                        and key.value == "role"
                        and isinstance(val, ast.Constant)
                        and val.value == "system"
                    ):
                        return True
        return False

class NoModerationCheckRule(AuditRule):

    id = "AUD007"
    description = "Detects LLM usage without any moderation or safety checking"
    severity = "medium"

    _MODERATION_NAMES: set[str] = {
        "moderate", "moderation", "moderations",
        "content_filter", "safety_check", "check_safety",
        "toxicity", "classify", "guardrail", "guardrails",
    }

    def match(self, tree: ast.Module, file_path: str) -> list[AuditFinding]:
        if not _has_llm_import(tree):
            return []

        llm_calls = find_function_calls(tree, _LLM_CALL_NAMES)
        if not llm_calls:
            return []

        mod_calls = find_function_calls(tree, self._MODERATION_NAMES)
        has_moderation_import = False
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if "moderation" in node.module.lower() or "safety" in node.module.lower():
                    has_moderation_import = True
                    break

        if mod_calls or has_moderation_import:
            return []

        first = llm_calls[0]
        return [
            self._finding(
                file_path,
                getattr(first, "lineno", 0),
                "LLM calls detected without any moderation or safety "
                "checking in the same module.",
                "Add input/output moderation (e.g., OpenAI Moderations API, "
                "custom content filters) to detect harmful content.",
            )
        ]

class DangerousExecRule(AuditRule):

    id = "AUD008"
    description = "Detects model output being passed to exec(), eval(), subprocess, or os.system()"
    severity = "critical"

    _DANGEROUS_NAMES: set[str] = {
        "exec", "eval", "system", "popen",
        "run", "call", "check_output", "check_call",
        "Popen",
    }

    def match(self, tree: ast.Module, file_path: str) -> list[AuditFinding]:
        if not _has_llm_import(tree):
            return []
        findings: list[AuditFinding] = []

        llm_lines = _collect_llm_call_lines(tree)
        if not llm_lines:
            return []

        dangerous_calls = find_function_calls(tree, self._DANGEROUS_NAMES)
        for call_node in dangerous_calls:
            line = getattr(call_node, "lineno", 0)
            func = call_node.func

            is_dangerous = False
            if isinstance(func, ast.Name) and func.id in {"exec", "eval"}:
                is_dangerous = True
            elif isinstance(func, ast.Attribute):
                if func.attr == "system" and isinstance(func.value, ast.Name) and func.value.id == "os":
                    is_dangerous = True
                elif isinstance(func.value, ast.Name) and func.value.id == "subprocess":
                    is_dangerous = True

            if is_dangerous and any(ll < line for ll in llm_lines):
                findings.append(
                    self._finding(
                        file_path,
                        line,
                        "Potentially dangerous code execution function called "
                        "after LLM response; model output may flow into "
                        "exec/eval/subprocess.",
                        "Never pass unsanitised LLM output to code execution "
                        "functions. Use a sandboxed execution environment if "
                        "code execution is required.",
                    )
                )
        return findings

ALL_RULES: list[AuditRule] = [
    PromptConcatenationRule(),
    NoOutputValidationRule(),
    ExposedToolsRule(),
    HardcodedSecretsInPromptsRule(),
    UnsafeRetrievalInjectionRule(),
    MissingSystemMessageRule(),
    NoModerationCheckRule(),
    DangerousExecRule(),
]

def get_rules(ids: list[str] | None = None) -> list[AuditRule]:
    if ids is None:
        return list(ALL_RULES)
    id_set = set(ids)
    return [r for r in ALL_RULES if r.id in id_set]

def _names_in_node(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
