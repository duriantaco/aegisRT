from __future__ import annotations

from abc import ABC, abstractmethod

from aegisrt.core.result import TestCase

class BaseGenerator(ABC):

    @abstractmethod
    def generate(self, seeds: list[str], probe_id: str, **kwargs) -> list[TestCase]:
        pass
