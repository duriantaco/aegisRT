from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AgentToolCall(BaseModel):
    name: str
    arguments: Any = None
    output: Any = None
    status: str | None = None
    error: str | None = None
    trust_boundary: str | None = None
    memory_store: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RetrievalContextItem(BaseModel):
    content: str
    source_id: str | None = None
    title: str | None = None
    uri: str | None = None
    query: str | None = None
    score: float | None = None
    trust_boundary: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentMemoryAccess(BaseModel):
    store: str
    operation: str
    key: str | None = None
    value: Any = None
    trust_boundary: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentHandoff(BaseModel):
    from_agent: str
    to_agent: str
    reason: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentStep(BaseModel):
    step_id: str | None = None
    type: str = "message"
    agent_id: str | None = None
    agent_role: str | None = None
    content: Any = None
    input: Any = None
    output: Any = None
    tool_name: str | None = None
    trust_boundary: str | None = None
    memory_store: str | None = None
    timestamp: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentResponse(BaseModel):
    output_text: str
    raw: Any = None
    latency_ms: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)
    session_id: str | None = None
    attack_id: str | None = None
    tools_called: list[AgentToolCall] = Field(default_factory=list)
    retrieval_context: list[RetrievalContextItem] = Field(default_factory=list)
    memory_accesses: list[AgentMemoryAccess] = Field(default_factory=list)
    handoffs: list[AgentHandoff] = Field(default_factory=list)
    steps: list[AgentStep] = Field(default_factory=list)
