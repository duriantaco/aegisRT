from __future__ import annotations

import time
from typing import Any

import httpx

from aegisrt.config.models import TargetConfig
from aegisrt.targets.base import BaseTarget, TargetResponse

class FastApiTarget(BaseTarget):

    def __init__(
        self,
        config: TargetConfig,
        *,
        app: Any | None = None,
    ) -> None:
        self._config = config
        self._app = app
        self._url = config.url or "http://testserver"
        self._method = (config.method or "POST").upper()
        self._timeout = config.timeout_seconds
        self._headers = config.headers or {}
        self._body_template = config.body_template
        self._params = config.params or {}
        self._client: httpx.Client | None = None

    def setup(self) -> None:
        if self._app is not None:
            transport = httpx.ASGITransport(app=self._app)
            self._client = httpx.Client(
                transport=transport,
                base_url=self._url,
                timeout=httpx.Timeout(self._timeout),
                headers=self._headers,
            )
        else:
            if not self._config.url:
                raise ValueError(
                    "FastApiTarget requires either an ASGI app instance or a url in config"
                )
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

        body = self._build_body(prompt)
        if self._app is None:
            url = self._url
        else:
            url = "/"

        if self._body_template and "_path" in self._body_template:
            url = self._body_template["_path"]
            body.pop("_path", None)

        start = time.perf_counter()
        try:
            response = self._client.request(
                method=self._method,
                url=url,
                json=body,
                params=self._params if self._params else None,
            )
            elapsed_ms = (time.perf_counter() - start) * 1000

            try:
                raw_json = response.json()
                text = self._extract_text(raw_json)
            except Exception:
                raw_json = None
                text = response.text

            return TargetResponse(
                text=text,
                raw=raw_json if raw_json is not None else response.text,
                latency_ms=elapsed_ms,
                metadata={
                    "status_code": response.status_code,
                    "in_process": self._app is not None,
                },
            )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            return TargetResponse(
                text=f"[ERROR] {type(exc).__name__}: {exc}",
                raw=str(exc),
                latency_ms=elapsed_ms,
                metadata={"error": True},
            )

    def _build_body(self, prompt: str) -> dict:
        if self._body_template:
            import copy
            return self._substitute(copy.deepcopy(self._body_template), prompt)
        return {"prompt": prompt}

    @staticmethod
    def _substitute(obj: Any, prompt: str) -> Any:
        if isinstance(obj, str):
            return obj.replace("{{prompt}}", prompt)
        elif isinstance(obj, dict):
            return {k: FastApiTarget._substitute(v, prompt) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [FastApiTarget._substitute(item, prompt) for item in obj]
        return obj

    @staticmethod
    def _extract_text(data: Any) -> str:
        import json

        if isinstance(data, dict):
            choices = data.get("choices")
            if isinstance(choices, list) and choices:
                msg = choices[0].get("message", {})
                if "content" in msg:
                    return str(msg["content"])
            for key in ("text", "response", "output", "result", "content"):
                if key in data:
                    return str(data[key])
        return json.dumps(data)
