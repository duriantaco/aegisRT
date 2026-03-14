
from __future__ import annotations

import logging

from pydantic import BaseModel, Field

from aegisrt.config.models import ProbeConfig

logger = logging.getLogger(__name__)

class Suite(BaseModel):

    name: str
    description: str
    probes: list[ProbeConfig] = Field(default_factory=list)

class SuiteRegistry:

    def __init__(self) -> None:
        self._suites: dict[str, Suite] = {}

    def register(self, suite: Suite) -> None:
        self._suites[suite.name] = suite
        logger.debug("Registered suite: %s", suite.name)

    def get(self, name: str) -> Suite | None:
        return self._suites.get(name)

    def list_suites(self) -> list[str]:
        return sorted(self._suites.keys())

    def load_builtins(self) -> None:
        from aegisrt.suites.builtins import get_builtin_suites

        for suite in get_builtin_suites():
            self.register(suite)
