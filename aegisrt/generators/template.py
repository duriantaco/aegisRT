from __future__ import annotations

import hashlib
import itertools
import re

from aegisrt.core.result import TestCase
from aegisrt.generators.base import BaseGenerator

_TEMPLATE_VAR_RE = re.compile(r"\{\{(\w+)\}\}")

class TemplateGenerator(BaseGenerator):

    def __init__(self, variables: dict[str, list[str]] | None = None) -> None:
        self.variables = variables or {}

    def generate(self, seeds: list[str], probe_id: str, **kwargs) -> list[TestCase]:
        cases: list[TestCase] = []
        for seed in seeds:
            var_names = _TEMPLATE_VAR_RE.findall(seed)
            if not var_names:
                cases.append(self._make_case(probe_id, seed, {}))
                continue

            seen: set[str] = set()
            unique_vars: list[str] = []
            for name in var_names:
                if name not in seen:
                    seen.add(name)
                    unique_vars.append(name)

            value_lists: list[list[str]] = []
            for var in unique_vars:
                values = self.variables.get(var)
                if not values:
                    value_lists.append([f"{{{{{var}}}}}"])
                else:
                    value_lists.append(values)

            for combo in itertools.product(*value_lists):
                substitutions = dict(zip(unique_vars, combo))
                expanded = seed
                for var_name, value in substitutions.items():
                    expanded = expanded.replace(f"{{{{{var_name}}}}}", value)
                cases.append(self._make_case(probe_id, expanded, substitutions))

        return cases

    @staticmethod
    def _make_case(
        probe_id: str,
        text: str,
        substitutions: dict[str, str],
    ) -> TestCase:
        digest = hashlib.sha256(f"{probe_id}:template:{text}".encode()).hexdigest()
        return TestCase(
            id=digest[:16],
            probe_id=probe_id,
            input_text=text,
            metadata={
                "generator": "template",
                "substitutions": substitutions,
            },
        )
