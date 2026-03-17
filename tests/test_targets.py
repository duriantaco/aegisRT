from __future__ import annotations

from aegisrt.config.models import TargetConfig
from aegisrt.targets.agent import (
    AgentHandoff,
    AgentMemoryAccess,
    AgentResponse,
    AgentStep,
    AgentToolCall,
    RetrievalContextItem,
)
from aegisrt.targets.base import TargetResponse
from aegisrt.targets.callback import CallbackTarget
from aegisrt.targets.http import HttpTarget

def test_callback_target_executes_function():
    target = CallbackTarget(fn=lambda prompt: f"Echo: {prompt}")
    response = target.execute("hello")
    assert isinstance(response, TargetResponse)
    assert response.text == "Echo: hello"

def test_callback_target_measures_latency():
    target = CallbackTarget(fn=lambda p: "ok")
    response = target.execute("test")
    assert response.latency_ms > 0

def test_callback_target_injects_declared_model_metadata():
    target = CallbackTarget(fn=lambda p: "ok", model_name="gpt-4o")
    response = target.execute("test")
    assert response.metadata["model"] == "gpt-4o"

def test_callback_target_preserves_target_response_metadata():
    target = CallbackTarget(
        fn=lambda p: TargetResponse(text="ok", metadata={"provider": "demo"}),
        model_name="gpt-4.1-mini",
    )
    response = target.execute("test")
    assert response.text == "ok"
    assert response.metadata["provider"] == "demo"
    assert response.metadata["model"] == "gpt-4.1-mini"

def test_callback_target_accepts_structured_agent_response():
    target = CallbackTarget(
        fn=lambda p: AgentResponse(
            output_text=f"Agent handled: {p}",
            session_id="sess-1",
            attack_id="attack-1",
            tools_called=[
                AgentToolCall(
                    name="web_search",
                    arguments={"query": p},
                    output="result",
                    trust_boundary="external_tool",
                )
            ],
            retrieval_context=[
                RetrievalContextItem(
                    content="retrieved chunk",
                    source_id="doc-1",
                    query=p,
                    trust_boundary="vector_store",
                )
            ],
            memory_accesses=[
                AgentMemoryAccess(
                    store="episodic",
                    operation="read",
                    key="user_profile",
                    value={"tier": "gold"},
                )
            ],
            handoffs=[
                AgentHandoff(from_agent="planner", to_agent="executor", reason="delegate")
            ],
            steps=[
                AgentStep(
                    step_id="plan-1",
                    type="message",
                    agent_id="planner",
                    agent_role="planner",
                    content="Plan created",
                )
            ],
        ),
        model_name="gpt-4.1-mini",
    )

    response = target.execute("find docs")

    assert response.text == "Agent handled: find docs"
    assert response.metadata["session_id"] == "sess-1"
    assert response.metadata["attack_id"] == "attack-1"
    assert response.metadata["tools_called"][0]["name"] == "web_search"
    assert response.metadata["retrieval_context"][0]["source_id"] == "doc-1"
    assert response.metadata["memory_accesses"][0]["store"] == "episodic"
    assert response.metadata["handoffs"][0]["to_agent"] == "executor"
    assert response.metadata["session_steps"][0]["agent_id"] == "planner"
    assert response.metadata["model"] == "gpt-4.1-mini"

def test_callback_target_handles_exception():
    def explode(prompt: str) -> str:
        raise RuntimeError("boom")

    target = CallbackTarget(fn=explode)
    response = target.execute("trigger")

    assert "[ERROR]" in response.text
    assert "RuntimeError" in response.text
    assert "boom" in response.text
    assert response.metadata.get("error") is True
    assert response.latency_ms > 0

def test_target_response_model():
    resp = TargetResponse(
        text="hi",
        raw={"message": "hi"},
        latency_ms=5.0,
        metadata={"status_code": 200},
    )
    assert resp.text == "hi"
    assert resp.raw == {"message": "hi"}
    assert resp.latency_ms == 5.0
    assert resp.metadata["status_code"] == 200

def test_target_response_defaults():
    resp = TargetResponse(text="hello")
    assert resp.raw is None
    assert resp.latency_ms == 0.0
    assert resp.metadata == {}

def test_http_target_init():
    cfg = TargetConfig(
        type="http",
        url="https://example.com/v1/chat",
        method="POST",
        headers={"Authorization": "Bearer test"},
        body_template={"prompt": "{{prompt}}"},
        timeout_seconds=10,
        retries=3,
    )
    target = HttpTarget(cfg)
    assert target._url == "https://example.com/v1/chat"
    assert target._method == "POST"
    assert target._headers == {"Authorization": "Bearer test"}
    assert target._body_template == {"prompt": "{{prompt}}"}
    assert target._timeout == 10
    assert target._retries == 3

def test_http_target_requires_url():
    cfg = TargetConfig(type="http")
    try:
        HttpTarget(cfg)
        assert False, "Should have raised ValueError"
    except ValueError as exc:
        assert "url" in str(exc).lower()
