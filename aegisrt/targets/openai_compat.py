from __future__ import annotations

import json
import time
from typing import Any

import httpx

from aegisrt.config.models import TargetConfig
from aegisrt.targets.base import BaseTarget, TargetResponse

class OpenAiCompatTarget(BaseTarget):

    def __init__(self, config: TargetConfig) -> None:
        if not config.url:
            raise ValueError("OpenAiCompatTarget requires a url in TargetConfig")

        self._url = config.url
        self._method = (config.method or "POST").upper()
        self._headers = config.headers or {}
        self._timeout = config.timeout_seconds
        self._retries = config.retries

        params = config.params or {}
        self._model: str = params.get("model", "default")
        self._system_message: str | None = params.get("system_message")
        self._temperature: float | None = (
            float(params["temperature"]) if "temperature" in params else None
        )
        self._max_tokens: int | None = (
            int(params["max_tokens"]) if "max_tokens" in params else None
        )

        self._is_anthropic = "anthropic.com" in self._url

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

    def _build_request_body(self, prompt: str) -> dict[str, Any]:
        messages: list[dict[str, str]] = []

        if self._is_anthropic:
            messages.append({"role": "user", "content": prompt})
            body: dict[str, Any] = {
                "model": self._model,
                "messages": messages,
                "max_tokens": self._max_tokens or 1024,
            }
            if self._system_message:
                body["system"] = self._system_message
        else:
            if self._system_message:
                messages.append({"role": "system", "content": self._system_message})
            messages.append({"role": "user", "content": prompt})
            body = {
                "model": self._model,
                "messages": messages,
            }
            if self._max_tokens is not None:
                body["max_tokens"] = self._max_tokens

        if self._temperature is not None:
            body["temperature"] = self._temperature
        return body

    def execute(self, prompt: str) -> TargetResponse:
        if self._client is None:
            self.setup()
        assert self._client is not None

        body = self._build_request_body(prompt)

        last_exc: Exception | None = None
        start = time.perf_counter()

        for attempt in range(1, self._retries + 1):
            start = time.perf_counter()
            try:
                response = self._client.request(
                    method=self._method, url=self._url, json=body
                )
                elapsed_ms = (time.perf_counter() - start) * 1000

                try:
                    raw_json = response.json()
                    text = self._extract_text(raw_json)
                except (json.JSONDecodeError, ValueError):
                    raw_json = None
                    text = response.text

                prompt_tokens = 0
                completion_tokens = 0
                total_tokens = 0
                if isinstance(raw_json, dict):
                    usage = raw_json.get("usage")
                    if isinstance(usage, dict):
                        prompt_tokens = usage.get("prompt_tokens", 0)
                        completion_tokens = usage.get("completion_tokens", 0)
                        if prompt_tokens == 0:
                            prompt_tokens = usage.get("input_tokens", 0)
                        if completion_tokens == 0:
                            completion_tokens = usage.get("output_tokens", 0)
                        total_tokens = usage.get("total_tokens", 0)
                        if total_tokens == 0:
                            total_tokens = prompt_tokens + completion_tokens

                return TargetResponse(
                    text=text,
                    raw=raw_json if raw_json is not None else response.text,
                    latency_ms=elapsed_ms,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=total_tokens,
                    metadata={
                        "status_code": response.status_code,
                        "model": self._model,
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
                message = choices[0].get("message", {})
                content = message.get("content")
                if content is not None:
                    return str(content)
                delta = choices[0].get("delta", {})
                if "content" in delta:
                    return str(delta["content"])
                if "text" in choices[0]:
                    return str(choices[0]["text"])

            content_blocks = data.get("content")
            if isinstance(content_blocks, list) and content_blocks:
                for block in content_blocks:
                    if isinstance(block, dict) and block.get("type") == "text":
                        text = block.get("text", "")
                        if text:
                            return text

            if "error" in data:
                err = data["error"]
                if isinstance(err, dict):
                    return f"[API ERROR] {err.get('message', err)}"
                return f"[API ERROR] {err}"
        return json.dumps(data)
