from __future__ import annotations

from pydantic import BaseModel, Field


class TestCase(BaseModel):
    __test__ = False

    id: str
    probe_id: str
    input_text: str
    metadata: dict = Field(default_factory=dict)


class Detection(BaseModel):
    __test__ = False

    detector: str
    triggered: bool
    score: float
    evidence: dict = Field(default_factory=dict)


class TestResult(BaseModel):
    __test__ = False

    case_id: str
    probe_id: str
    input_text: str = ""
    response_text: str = ""
    passed: bool
    score: float
    severity: str
    confidence: float
    evidence: dict = Field(default_factory=dict)
    remediation: list[str] = Field(default_factory=list)
    trace: dict = Field(default_factory=dict)


class RunReport(BaseModel):
    __test__ = False

    run_id: str
    timestamp: str
    target_info: dict = Field(default_factory=dict)
    results: list[TestResult] = Field(default_factory=list)
    summary: dict = Field(default_factory=dict)
    config: dict = Field(default_factory=dict)
    metrics: dict = Field(default_factory=dict)
