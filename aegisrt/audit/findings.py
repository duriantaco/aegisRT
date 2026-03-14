
from __future__ import annotations

from pydantic import BaseModel, Field

class AuditFinding(BaseModel):

    rule_id: str
    file_path: str
    line: int
    message: str
    severity: str
    remediation: str
    code_snippet: str = ""

class AuditReport(BaseModel):

    findings: list[AuditFinding] = Field(default_factory=list)
    scanned_files: int = 0
    summary: dict = Field(default_factory=dict)
