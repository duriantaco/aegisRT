from __future__ import annotations

import time
from typing import Callable

from aegisrt.targets.base import BaseTarget, TargetResponse

class CallbackTarget(BaseTarget):

    def __init__(
        self,
        fn: Callable[[str], str | TargetResponse],
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
        metadata = {"model": self._model_name} if self._model_name else {}
        return TargetResponse(
            text=str(result),
            raw=result,
            latency_ms=elapsed_ms,
            metadata=metadata,
        )
