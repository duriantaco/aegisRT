from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def _first_nonempty(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return []


def _normalize_explicit_step(step: Any, index: int) -> dict[str, Any]:
    if isinstance(step, str):
        return {
            "step_id": f"step-{index + 1}",
            "type": "message",
            "content": step,
        }

    payload = dict(step) if isinstance(step, Mapping) else {"content": str(step)}
    tool_call = _as_mapping(payload.get("tool_call"))
    tool_result = _as_mapping(payload.get("tool_result"))

    normalized = dict(payload)
    normalized["step_id"] = str(
        _first_nonempty(
            payload.get("step_id"),
            payload.get("id"),
            payload.get("name"),
            f"step-{index + 1}",
        )
    )
    parent_step_id = _first_nonempty(
        payload.get("parent_step_id"),
        payload.get("parent_id"),
    )
    if parent_step_id is not None:
        normalized["parent_step_id"] = str(parent_step_id)

    agent_role = _first_nonempty(
        payload.get("agent_role"),
        payload.get("role"),
        payload.get("speaker_role"),
    )
    if agent_role is not None:
        normalized["agent_role"] = str(agent_role)

    agent_id = _first_nonempty(
        payload.get("agent_id"),
        payload.get("agent"),
        payload.get("speaker"),
        payload.get("name"),
        agent_role,
    )
    if agent_id is not None:
        normalized["agent_id"] = str(agent_id)

    step_type = _first_nonempty(
        payload.get("type"),
        payload.get("step_type"),
        payload.get("event"),
        "message",
    )
    normalized["type"] = str(step_type)

    content = _first_nonempty(
        payload.get("content"),
        payload.get("message"),
        payload.get("text"),
        payload.get("summary"),
    )
    if content is not None:
        normalized["content"] = content

    input_payload = _first_nonempty(
        payload.get("input"),
        payload.get("prompt"),
        payload.get("tool_input"),
        tool_call.get("arguments"),
        tool_call.get("input"),
    )
    if input_payload is not None:
        normalized["input"] = input_payload

    output_payload = _first_nonempty(
        payload.get("output"),
        payload.get("result"),
        payload.get("tool_output"),
        tool_result.get("output"),
        tool_result.get("result"),
    )
    if output_payload is not None:
        normalized["output"] = output_payload

    tool_name = _first_nonempty(
        payload.get("tool_name"),
        payload.get("tool"),
        tool_call.get("name"),
    )
    if tool_name is not None:
        normalized["tool_name"] = str(tool_name)

    memory_store = _first_nonempty(
        payload.get("memory_store"),
        payload.get("memory"),
        payload.get("store"),
    )
    if memory_store is not None:
        normalized["memory_store"] = str(memory_store)

    trust_boundary = _first_nonempty(
        payload.get("trust_boundary"),
        payload.get("boundary"),
    )
    if trust_boundary is not None:
        normalized["trust_boundary"] = str(trust_boundary)

    timestamp = _first_nonempty(payload.get("timestamp"), payload.get("at"))
    if timestamp is not None:
        normalized["timestamp"] = str(timestamp)

    return normalized


def _normalize_conversation_steps(conversation_trace: Sequence[Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for index, turn in enumerate(conversation_trace):
        if not isinstance(turn, Mapping):
            steps.append(
                {
                    "step_id": f"turn-{index + 1}",
                    "type": "message",
                    "agent_role": "unknown",
                    "agent_id": "unknown",
                    "content": str(turn),
                }
            )
            continue

        role = str(_first_nonempty(turn.get("agent_role"), turn.get("role"), "unknown"))
        agent_id = str(
            _first_nonempty(turn.get("agent_id"), turn.get("speaker"), role)
        )
        step = dict(turn)
        step["step_id"] = str(_first_nonempty(turn.get("step_id"), f"turn-{index + 1}"))
        step["type"] = str(_first_nonempty(turn.get("type"), "message"))
        step["agent_role"] = role
        step["agent_id"] = agent_id
        if "content" not in step and "text" in turn:
            step["content"] = turn["text"]
        steps.append(step)
    return steps


def normalize_session_steps(raw_steps: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_steps, Sequence) or isinstance(raw_steps, (str, bytes, bytearray)):
        return []
    return [_normalize_explicit_step(step, index) for index, step in enumerate(raw_steps)]


def get_trace_session_id(trace: Mapping[str, Any] | None, *, fallback: str | None = None) -> str | None:
    payload = _as_mapping(trace)
    case_metadata = _as_mapping(_as_mapping(payload.get("case")).get("metadata"))
    value = _first_nonempty(
        payload.get("session_id"),
        payload.get("attack_session_id"),
        case_metadata.get("session_id"),
        case_metadata.get("attack_session_id"),
        case_metadata.get("conversation_id"),
        case_metadata.get("conversation_case_id"),
        fallback,
    )
    return str(value) if value not in (None, "") else None


def build_session_trace(
    case_metadata: Mapping[str, Any] | None,
    response_metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    case_meta = _as_mapping(case_metadata)
    response_meta = _as_mapping(response_metadata)

    session_id = _first_nonempty(
        case_meta.get("session_id"),
        case_meta.get("attack_session_id"),
        case_meta.get("conversation_id"),
        case_meta.get("conversation_case_id"),
        response_meta.get("session_id"),
    )
    attack_id = _first_nonempty(
        case_meta.get("attack_id"),
        response_meta.get("attack_id"),
        case_meta.get("conversation_case_id"),
        session_id,
    )

    raw_steps = _first_nonempty(
        case_meta.get("steps"),
        case_meta.get("session_steps"),
        case_meta.get("attack_steps"),
    )
    steps = normalize_session_steps(raw_steps)

    if not steps:
        steps = _normalize_conversation_steps(_as_list(case_meta.get("conversation_trace")))

    payload: dict[str, Any] = {}
    if session_id is not None:
        payload["session_id"] = str(session_id)
    if attack_id is not None:
        payload["attack_id"] = str(attack_id)
    if steps:
        payload["steps"] = steps
    return payload
