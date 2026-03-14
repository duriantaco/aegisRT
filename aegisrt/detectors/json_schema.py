from __future__ import annotations

import json
from typing import Any

from aegisrt.core.result import TestCase, Detection
from aegisrt.targets.base import TargetResponse
from aegisrt.detectors.base import BaseDetector


def _validate_schema(data: Any, schema: dict) -> list[str]:
    errors: list[str] = []

    expected_type = schema.get("type")
    if expected_type:
        type_map = {
            "object": dict,
            "array": list,
            "string": str,
            "number": (int, float),
            "integer": int,
            "boolean": bool,
            "null": type(None),
        }
        expected_cls = type_map.get(expected_type)
        if expected_cls and not isinstance(data, expected_cls):
            errors.append(
                f"Expected type '{expected_type}', got '{type(data).__name__}'"
            )
            return errors

    if isinstance(data, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in data:
                errors.append(f"Missing required key: '{key}'")

        properties = schema.get("properties", {})
        for key, sub_schema in properties.items():
            if key in data:
                errors.extend(_validate_schema(data[key], sub_schema))

    if isinstance(data, list):
        items_schema = schema.get("items")
        if items_schema:
            for idx, item in enumerate(data):
                sub_errors = _validate_schema(item, items_schema)
                errors.extend(f"[{idx}] {e}" for e in sub_errors)

    return errors


class JsonSchemaDetector(BaseDetector):

    id: str = "json_schema"

    def __init__(
        self,
        *,
        detector_id: str = "json_schema",
        schema: dict | None = None,
    ) -> None:
        self.id = detector_id
        self.schema = schema

    def check(self, case: TestCase, response: TargetResponse) -> Detection:
        text = response.text.strip()
        errors: list[str] = []
        parsed: Any = None

        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError) as exc:
            errors.append(f"Invalid JSON: {exc}")

        if parsed is not None and self.schema is not None:
            schema_errors = _validate_schema(parsed, self.schema)
            errors.extend(schema_errors)

        triggered = len(errors) > 0
        score = min(1.0, len(errors) * 0.25)
        return Detection(
            detector=self.id,
            triggered=triggered,
            score=score,
            evidence={
                "valid_json": parsed is not None,
                "schema_provided": self.schema is not None,
                "errors": errors,
            },
        )
