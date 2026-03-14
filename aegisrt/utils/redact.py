
from __future__ import annotations

import re

from pydantic import BaseModel, Field

class RedactionConfig(BaseModel):

    patterns: list[str] = Field(default_factory=list)
    replacement: str = "***REDACTED***"

_DEFAULT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*)[A-Za-z0-9/+=]{40}"),
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)((?:api[_-]?key|apikey)\s*[:=]\s*['\"]?)[A-Za-z0-9_\-]{16,}"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9_\-.]{20,}"),
    re.compile(r"(?i)((?:password|passwd|pwd)\s*[:=]\s*['\"]?)[^\s'\"]{4,}"),
    re.compile(r"(?i)((?:token|secret)\s*[:=]\s*['\"]?)[A-Za-z0-9_\-]{16,}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),
]

def redact_secrets(text: str, config: RedactionConfig | None = None) -> str:
    replacement = "***REDACTED***"
    if config is not None:
        replacement = config.replacement

    patterns: list[re.Pattern[str]]
    if config and config.patterns:
        patterns = [re.compile(p) for p in config.patterns]
    else:
        patterns = _DEFAULT_PATTERNS

    result = text
    for pat in patterns:
        result = pat.sub(_make_replacer(replacement), result)
    return result

def _make_replacer(replacement: str):

    def _replacer(m: re.Match) -> str:
        groups = m.groups()
        if groups:
            prefix = groups[0] if groups[0] else ""
            if m.group(0).startswith(prefix):
                return prefix + replacement
        return replacement

    return _replacer
