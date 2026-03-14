from __future__ import annotations

import re

from aegisrt.core.result import TestCase, Detection
from aegisrt.targets.base import TargetResponse
from aegisrt.detectors.base import BaseDetector


class RegexDetector(BaseDetector):

    id: str = "regex"

    def __init__(
        self,
        patterns: list[str],
        *,
        detector_id: str = "regex",
        case_sensitive: bool = False,
    ) -> None:
        self.id = detector_id
        self.patterns = [
            re.compile(p, 0 if case_sensitive else re.IGNORECASE)
            for p in patterns
        ]
        self._raw_patterns = patterns

    def check(self, case: TestCase, response: TargetResponse) -> Detection:
        text = response.text
        matched: list[str] = []
        for pattern in self.patterns:
            match = pattern.search(text)
            if match:
                matched.append(match.group())

        triggered = len(matched) > 0
        score = min(1.0, len(matched) / max(len(self.patterns), 1))
        return Detection(
            detector=self.id,
            triggered=triggered,
            score=score,
            evidence={
                "matched_patterns": matched,
                "pattern_count": len(matched),
                "total_patterns": len(self.patterns),
            },
        )


class ForbiddenStringsDetector(BaseDetector):

    id: str = "forbidden_strings"

    def __init__(
        self,
        forbidden: list[str],
        *,
        detector_id: str = "forbidden_strings",
        case_sensitive: bool = False,
    ) -> None:
        self.id = detector_id
        self.case_sensitive = case_sensitive
        self.forbidden = forbidden

    def check(self, case: TestCase, response: TargetResponse) -> Detection:
        if self.case_sensitive:
            text = response.text
        else:
            text = response.text.lower()
        found: list[str] = []
        for item in self.forbidden:
            if self.case_sensitive:
                check_item = item
            else:
                check_item = item.lower()
            if check_item in text:
                found.append(item)

        triggered = len(found) > 0
        score = min(1.0, len(found) / max(len(self.forbidden), 1))
        return Detection(
            detector=self.id,
            triggered=triggered,
            score=score,
            evidence={
                "found_strings": found,
                "found_count": len(found),
                "total_forbidden": len(self.forbidden),
            },
        )
