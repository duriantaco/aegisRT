from __future__ import annotations

from abc import ABC, abstractmethod

from aegisrt.core.result import TestCase, TestResult, Detection
from aegisrt.targets.base import TargetResponse


class BaseEvaluator(ABC):

    @abstractmethod
    def evaluate(
        self,
        case: TestCase,
        response: TargetResponse,
        detections: list[Detection],
    ) -> TestResult:
        pass
