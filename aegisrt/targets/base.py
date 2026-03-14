from __future__ import annotations

from abc import ABC, abstractmethod

from pydantic import BaseModel, Field


class TargetResponse(BaseModel):

    text: str
    raw: dict | str | None = None
    latency_ms: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    metadata: dict = Field(default_factory=dict)


class BaseTarget(ABC):

    @abstractmethod
    def execute(self, prompt: str) -> TargetResponse:
        pass

    def setup(self) -> None:
        pass

    def teardown(self) -> None:
        pass
