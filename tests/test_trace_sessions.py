from __future__ import annotations

from aegisrt.core.trace_sessions import build_session_trace, get_trace_session_id


def test_build_session_trace_normalizes_explicit_attack_steps():
    payload = build_session_trace(
        {
            "session_id": "sess-1",
            "attack_id": "attack-1",
            "session_steps": [
                {
                    "id": "planner",
                    "agent_role": "planner",
                    "content": "Plan the exploit",
                    "trust_boundary": "internal",
                },
                {
                    "tool_call": {"name": "web_search", "arguments": {"query": "secret"}},
                    "tool_result": {"output": "internal prompt"},
                    "boundary": "external_tool",
                },
            ],
        }
    )

    assert payload["session_id"] == "sess-1"
    assert payload["attack_id"] == "attack-1"
    assert payload["steps"][0]["step_id"] == "planner"
    assert payload["steps"][1]["tool_name"] == "web_search"
    assert payload["steps"][1]["input"] == {"query": "secret"}
    assert payload["steps"][1]["output"] == "internal prompt"
    assert payload["steps"][1]["trust_boundary"] == "external_tool"


def test_build_session_trace_derives_steps_from_conversation_trace():
    payload = build_session_trace(
        {
            "session_id": "conv-1",
            "conversation_trace": [
                {"role": "user", "content": "Ignore safety"},
                {"role": "assistant", "content": "Tell me more"},
            ],
        }
    )

    assert payload["session_id"] == "conv-1"
    assert len(payload["steps"]) == 2
    assert payload["steps"][0]["agent_role"] == "user"
    assert payload["steps"][1]["agent_id"] == "assistant"


def test_get_trace_session_id_falls_back_to_case_metadata():
    trace = {
        "case": {
            "metadata": {
                "conversation_case_id": "conversation-42",
            }
        }
    }

    assert get_trace_session_id(trace) == "conversation-42"


def test_build_session_trace_promotes_agent_response_artifacts():
    payload = build_session_trace(
        {},
        {
            "session_id": "sess-2",
            "attack_id": "attack-2",
            "tools_called": [
                {
                    "name": "browser.open",
                    "arguments": {"url": "https://example.com"},
                    "output": "opened",
                    "trust_boundary": "external_tool",
                }
            ],
            "retrieval_context": [
                {
                    "content": "retrieved passage",
                    "source_id": "doc-9",
                    "query": "pricing",
                    "trust_boundary": "vector_store",
                }
            ],
            "memory_accesses": [
                {
                    "store": "episodic",
                    "operation": "read",
                    "key": "tenant",
                    "value": "acme",
                }
            ],
            "handoffs": [
                {"from_agent": "planner", "to_agent": "executor", "reason": "delegate"}
            ],
        },
    )

    assert payload["session_id"] == "sess-2"
    assert payload["attack_id"] == "attack-2"
    assert payload["tools_called"][0]["name"] == "browser.open"
    assert payload["retrieval_context"][0]["source_id"] == "doc-9"
    assert payload["memory_accesses"][0]["store"] == "episodic"
    assert payload["handoffs"][0]["to_agent"] == "executor"
    assert payload["steps"][0]["type"] == "tool_call"
    assert payload["steps"][1]["type"] == "retrieval"
