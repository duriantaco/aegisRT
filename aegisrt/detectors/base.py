from __future__ import annotations

from abc import ABC, abstractmethod

from aegisrt.core.result import TestCase, Detection
from aegisrt.targets.base import TargetResponse


class BaseDetector(ABC):

    id: str

    @abstractmethod
    def check(self, case: TestCase, response: TargetResponse) -> Detection:
        pass
