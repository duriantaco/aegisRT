from __future__ import annotations

from enum import IntEnum

from aegisrt.core.result import Detection


class SeverityLevel(IntEnum):

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


_SEVERITY_MAP: dict[str, SeverityLevel] = {
    "low": SeverityLevel.LOW,
    "medium": SeverityLevel.MEDIUM,
    "high": SeverityLevel.HIGH,
    "critical": SeverityLevel.CRITICAL,
}


def severity_rank(severity_str: str) -> int:
    return _SEVERITY_MAP.get(severity_str.lower(), SeverityLevel.MEDIUM).value


def infer_severity(probe_id: str, detections: list[Detection]) -> str:
    triggered = [d for d in detections if d.triggered]
    if not triggered:
        return "low"

    max_score = max(d.score for d in triggered)
    if max_score >= 0.9:
        return "critical"

    avg_score = sum(d.score for d in triggered) / len(triggered)
    if avg_score >= 0.7:
        return "high"

    return "medium"
