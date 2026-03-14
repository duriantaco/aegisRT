from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def _maybe_get(value: Any, key: str) -> Any:
    if isinstance(value, Mapping):
        return value.get(key)
    return getattr(value, key, None)


def extract_target_model(target: Any) -> str:
    for payload in (_maybe_get(target, "params"), _maybe_get(target, "body_template")):
        if not isinstance(payload, Mapping):
            continue
        for key in ("model", "model_name"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def extract_provider_model(provider: Any) -> str:
    value = _maybe_get(provider, "model")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return ""
