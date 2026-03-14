from __future__ import annotations

from aegisrt.core.result import Detection
from aegisrt.core.severity import SeverityLevel, severity_rank, infer_severity

def test_severity_levels_ordered():
    assert SeverityLevel.LOW < SeverityLevel.MEDIUM
    assert SeverityLevel.MEDIUM < SeverityLevel.HIGH
    assert SeverityLevel.HIGH < SeverityLevel.CRITICAL

def test_severity_rank():
    assert severity_rank("low") == 1
    assert severity_rank("medium") == 2
    assert severity_rank("high") == 3
    assert severity_rank("critical") == 4

def test_severity_rank_case_insensitive():
    assert severity_rank("HIGH") == 3
    assert severity_rank("Critical") == 4

def test_severity_rank_unknown():
    assert severity_rank("unknown_level") == 2

def test_infer_severity_no_detections():
    detections = [
        Detection(detector="test", triggered=False, score=0.0),
    ]
    assert infer_severity("test_probe", detections) == "low"

def test_infer_severity_empty():
    assert infer_severity("test_probe", []) == "low"

def test_infer_severity_with_detections_critical():
    detections = [
        Detection(detector="a", triggered=True, score=0.95),
    ]
    assert infer_severity("test_probe", detections) == "critical"

def test_infer_severity_with_detections_high():
    detections = [
        Detection(detector="a", triggered=True, score=0.75),
        Detection(detector="b", triggered=True, score=0.8),
    ]
    assert infer_severity("test_probe", detections) == "high"

def test_infer_severity_with_detections_medium():
    detections = [
        Detection(detector="a", triggered=True, score=0.3),
    ]
    assert infer_severity("test_probe", detections) == "medium"
