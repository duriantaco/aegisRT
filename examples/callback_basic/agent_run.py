# ruff: noqa: E402

"""Typed agent callback example for AegisRT.

Run with:
    python examples/callback_basic/agent_run.py
"""

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from aegisrt.config.models import ProbeConfig, ReportConfig, RunConfig, TargetConfig
from aegisrt.core.runner import SecurityRunner
from aegisrt.targets import (
    AgentMemoryAccess,
    AgentResponse,
    AgentStep,
    AgentToolCall,
    RetrievalContextItem,
)


def agent_callback(user_input: str) -> AgentResponse:
    return AgentResponse(
        output_text=f"I can help with that request: {user_input}",
        session_id="demo-session",
        attack_id="demo-attack",
        tools_called=[
            AgentToolCall(
                name="web_search",
                arguments={"query": user_input},
                output="sensitive internal result",
                trust_boundary="external_tool",
            )
        ],
        retrieval_context=[
            RetrievalContextItem(
                content="Internal runbook excerpt",
                source_id="kb-1",
                query=user_input,
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
        steps=[
            AgentStep(
                step_id="planner-1",
                type="message",
                agent_id="planner",
                agent_role="planner",
                content="Plan tool usage",
            ),
            AgentStep(
                step_id="tool-1",
                type="tool_call",
                agent_id="executor",
                agent_role="executor",
                tool_name="web_search",
                input={"query": user_input},
                output="sensitive internal result",
                trust_boundary="external_tool",
            ),
        ],
    )


def main() -> None:
    config = RunConfig(
        target=TargetConfig(type="callback", params={"model": "demo-agent"}),
        probes=[
            ProbeConfig(
                id="agent_tool_abuse",
                family="agent_tool_abuse",
            ),
            ProbeConfig(
                id="agent_cross_tenant",
                family="agent_cross_tenant",
                severity="critical",
            ),
        ],
        report=ReportConfig(formats=["terminal", "json"]),
    )

    runner = SecurityRunner(config, callback_fn=agent_callback)
    report = runner.run()

    first = report.results[0]
    print(
        "Agent trace:",
        first.trace.get("session_id"),
        len(first.trace.get("steps", [])),
        len(first.trace.get("tools_called", [])),
    )


if __name__ == "__main__":
    main()
