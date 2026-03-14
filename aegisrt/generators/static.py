from __future__ import annotations

import hashlib

from aegisrt.core.result import TestCase
from aegisrt.generators.base import BaseGenerator

class StaticGenerator(BaseGenerator):

    def generate(self, seeds: list[str], probe_id: str, **kwargs) -> list[TestCase]:
        cases: list[TestCase] = []
        for seed in seeds:
            case_id = self._make_id(probe_id, seed)
            cases.append(
                TestCase(
                    id=case_id,
                    probe_id=probe_id,
                    input_text=seed,
                    metadata={"generator": "static", **kwargs},
                )
            )
        return cases

    @staticmethod
    def _make_id(probe_id: str, text: str) -> str:
        digest = hashlib.sha256(f"{probe_id}:{text}".encode()).hexdigest()
        return digest[:16]
