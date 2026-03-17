from __future__ import annotations

import time
from typing import Callable

from aegisrt.targets.agent import AgentResponse
from aegisrt.targets.base import BaseTarget, TargetResponse

class CallbackTarget(BaseTarget):

    def __init__(
        self,
        fn: Callable[[str], str | TargetResponse | AgentResponse],
        *,
        model_name: str = "",
    ) -> None:
        self._fn = fn
        self._model_name = model_name.strip()

    def execute(self, prompt: str) -> TargetResponse:
        start = time.perf_counter()
        try:
            result = self._fn(prompt)
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            return TargetResponse(
                text=f"[ERROR] {type(exc).__name__}: {exc}",
                raw=str(exc),
                latency_ms=elapsed_ms,
                metadata={"error": True, "exception_type": type(exc).__name__},
            )
        elapsed_ms = (time.perf_counter() - start) * 1000
        if isinstance(result, TargetResponse):
            metadata = dict(result.metadata)
            if self._model_name and not metadata.get("model"):
                metadata["model"] = self._model_name
            return result.model_copy(
                update={
                    "latency_ms": result.latency_ms or elapsed_ms,
                    "metadata": metadata,
                }
            )
        if isinstance(result, AgentResponse):
            metadata = dict(result.metadata)
            if result.session_id and not metadata.get("session_id"):
                metadata["session_id"] = result.session_id
            if result.attack_id and not metadata.get("attack_id"):
                metadata["attack_id"] = result.attack_id
            if result.tools_called:
                metadata["tools_called"] = [
                    tool.model_dump(mode="json") for tool in result.tools_called
                ]
            if result.retrieval_context:
                metadata["retrieval_context"] = [
                    item.model_dump(mode="json") for item in result.retrieval_context
                ]
            if result.memory_accesses:
                metadata["memory_accesses"] = [
                    access.model_dump(mode="json")
                    for access in result.memory_accesses
                ]
            if result.handoffs:
                metadata["handoffs"] = [
                    handoff.model_dump(mode="json") for handoff in result.handoffs
                ]
            if result.steps:
                metadata["session_steps"] = [
                    step.model_dump(mode="json") for step in result.steps
                ]
            if self._model_name and not metadata.get("model"):
                metadata["model"] = self._model_name
            return TargetResponse(
                text=result.output_text,
                raw=result.raw,
                latency_ms=result.latency_ms or elapsed_ms,
                prompt_tokens=result.prompt_tokens,
                completion_tokens=result.completion_tokens,
                total_tokens=result.total_tokens,
                metadata=metadata,
            )
        metadata = {"model": self._model_name} if self._model_name else {}
        return TargetResponse(
            text=str(result),
            raw=result,
            latency_ms=elapsed_ms,
            metadata=metadata,
        )
