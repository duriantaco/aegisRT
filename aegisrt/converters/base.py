
from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod

from aegisrt.core.result import TestCase


class BaseConverter(ABC):

    id: str = "base"
    description: str = ""

    @abstractmethod
    def convert(self, text: str) -> str:
        ...

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(id={self.id!r})"


class ConverterPipeline:

    def __init__(
        self,
        converters: list[BaseConverter],
        *,
        keep_originals: bool = True,
    ) -> None:
        self.converters = converters
        self.keep_originals = keep_originals

    def apply(self, cases: list[TestCase]) -> list[TestCase]:
        if not self.converters:
            return cases

        result: list[TestCase] = []

        if self.keep_originals:
            result.extend(cases)

        chain_label = "+".join(c.id for c in self.converters)

        for case in cases:
            text = case.input_text
            for converter in self.converters:
                text = converter.convert(text)

            digest = hashlib.sha256(
                f"{case.probe_id}:converted:{chain_label}:{text}".encode()
            ).hexdigest()

            meta = dict(case.metadata)
            meta["converter_chain"] = chain_label
            meta["original_case_id"] = case.id
            meta["original_input_text"] = case.input_text

            result.append(
                TestCase(
                    id=digest[:16],
                    probe_id=case.probe_id,
                    input_text=text,
                    metadata=meta,
                )
            )

        return result

    def __repr__(self) -> str:
        names = [c.id for c in self.converters]
        return f"ConverterPipeline({names})"
