from __future__ import annotations

from typing import Any

from aegisrt.config.models import RunConfig


def generate_schema() -> dict[str, Any]:
    return RunConfig.model_json_schema()


def validate_config(data: dict[str, Any]) -> RunConfig:
    return RunConfig.model_validate(data)
