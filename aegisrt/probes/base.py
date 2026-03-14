from __future__ import annotations

from abc import ABC, abstractmethod

from aegisrt.core.result import TestCase
from aegisrt.detectors.base import BaseDetector
from aegisrt.generators.base import BaseGenerator

class BaseProbe(ABC):

    id: str
    family: str
    severity: str = "medium"
    description: str = ""

    @abstractmethod
    def get_seeds(self) -> list[str]:
        pass

    @abstractmethod
    def get_generator(self) -> BaseGenerator:
        pass

    @abstractmethod
    def get_detectors(self) -> list[BaseDetector]:
        pass

    def generate_cases(self, **kwargs) -> list[TestCase]:
        return self.get_generator().generate(self.get_seeds(), self.id, **kwargs)

    def remediation(self) -> list[str]:
        return []
