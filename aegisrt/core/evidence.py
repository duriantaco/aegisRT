from __future__ import annotations

from typing import Any

from aegisrt.core.result import Detection
from aegisrt.targets.base import TargetResponse


def collect_evidence(detections: list[Detection], response: TargetResponse) -> dict[str, Any]:
    collector = EvidenceCollector()
    for detection in detections:
        collector.add_detection(detection)
    collector.add_response_info(response)
    return collector.build()


class EvidenceCollector:

    def __init__(self) -> None:
        self._detections: list[dict[str, Any]] = []
        self._response_info: dict[str, Any] = {}
        self._extra: dict[str, Any] = {}

    def add_detection(self, detection: Detection) -> "EvidenceCollector":
        entry: dict[str, Any] = {
            "detector": detection.detector,
            "triggered": detection.triggered,
            "score": detection.score,
        }
        if detection.evidence:
            entry["details"] = detection.evidence
        self._detections.append(entry)
        return self

    def add_response_info(self, response: TargetResponse) -> "EvidenceCollector":
        self._response_info = {
            "response_length": len(response.text),
            "latency_ms": response.latency_ms,
        }
        if response.metadata:
            self._response_info["metadata"] = response.metadata
        return self

    def add_extra(self, key: str, value: Any) -> "EvidenceCollector":
        self._extra[key] = value
        return self

    def build(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if self._detections:
            result["detections"] = self._detections
            result["triggered_count"] = sum(1 for d in self._detections if d["triggered"])
            if self._detections:
                result["max_score"] = max(d["score"] for d in self._detections)
            else:
                result["max_score"] = 0.0
        if self._response_info:
            result["response"] = self._response_info
        if self._extra:
            result["extra"] = self._extra
        return result
