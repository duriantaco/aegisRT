from __future__ import annotations

import copy
import json
import time
from typing import Any

import httpx

from aegisrt.config.models import TargetConfig
from aegisrt.targets.base import BaseTarget, TargetResponse

_PROMPT_PLACEHOLDER = "{{prompt}}"

def _substitute_prompt(obj: Any, prompt: str) -> Any:
    if isinstance(obj, str):
        return obj.replace(_PROMPT_PLACEHOLDER, prompt)
    elif isinstance(obj, dict):
        return {k: _substitute_prompt(v, prompt) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_substitute_prompt(item, prompt) for item in obj]
    return obj

class HttpTarget(BaseTarget):

    def __init__(self, config: TargetConfig) -> None:
        if not config.url:
            raise ValueError("HttpTarget requires a url in TargetConfig")

        self._url = config.url
        self._method = (config.method or "POST").upper()
        self._headers = config.headers or {}
        self._body_template = config.body_template
        self._params = config.params or {}
        self._timeout = config.timeout_seconds
        self._retries = config.retries
        self._client: httpx.Client | None = None

    def setup(self) -> None:
        self._client = httpx.Client(
            timeout=httpx.Timeout(self._timeout),
            headers=self._headers,
        )

    def teardown(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def execute(self, prompt: str) -> TargetResponse:
        if self._client is None:
            self.setup()
        assert self._client is not None

        body: dict | None = None
        if self._body_template is not None:
            body = _substitute_prompt(copy.deepcopy(self._body_template), prompt)

        last_exc: Exception | None = None
        start = time.perf_counter()
        for attempt in range(1, self._retries + 1):
            start = time.perf_counter()
            try:
                response = self._client.request(
                    method=self._method,
                    url=self._url,
                    json=body,
                    params=self._params if self._params else None,
                )
                elapsed_ms = (time.perf_counter() - start) * 1000

                try:
                    raw_json = response.json()
                    text = self._extract_text(raw_json)
                except (json.JSONDecodeError, ValueError):
                    raw_json = None
                    text = response.text

                return TargetResponse(
                    text=text,
                    raw=raw_json if raw_json is not None else response.text,
                    latency_ms=elapsed_ms,
                    metadata={
                        "status_code": response.status_code,
                        "attempt": attempt,
                    },
                )
            except (httpx.HTTPError, httpx.TimeoutException) as exc:
                last_exc = exc
                continue

        elapsed_ms = (time.perf_counter() - start) * 1000
        return TargetResponse(
            text=f"[ERROR] {type(last_exc).__name__}: {last_exc}",
            raw=str(last_exc),
            latency_ms=elapsed_ms,
            metadata={"error": True, "attempts": self._retries},
        )

    @staticmethod
    def _extract_text(data: Any) -> str:
        if isinstance(data, dict):
            choices = data.get("choices")
            if isinstance(choices, list) and choices:
                msg = choices[0].get("message", {})
                if "content" in msg:
                    return str(msg["content"])
                if "text" in choices[0]:
                    return str(choices[0]["text"])
            for key in ("text", "response", "output", "result", "content"):
                if key in data:
                    return str(data[key])
        return json.dumps(data)
