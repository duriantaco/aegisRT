from __future__ import annotations

import base64
import codecs
import hashlib
from string import Template
from typing import Callable

from aegisrt.core.result import TestCase
from aegisrt.generators.base import BaseGenerator

_LEET_MAP: dict[str, str] = {
    "a": "4",
    "e": "3",
    "i": "1",
    "o": "0",
    "s": "5",
    "t": "7",
    "l": "1",
    "g": "9",
    "b": "8",
}

_UNICODE_CONFUSABLES: dict[str, str] = {
    "a": "\u0430",
    "c": "\u0441",
    "e": "\u0435",
    "o": "\u043e",
    "p": "\u0440",
    "s": "\u0455",
    "x": "\u0445",
    "y": "\u0443",
    "i": "\u0456",
    "d": "\u0501",
}

_ROLE_PREFIXES: list[str] = [
    "As an AI assistant, ",
    "You are a helpful assistant. ",
    "SYSTEM: ",
    "Assistant: Sure! ",
    "[INST] ",
]

_INSTRUCTION_TAG_TEMPLATES: list[str] = [
    "<instruction>$text</instruction>",
    "<system>$text</system>",
    "<|im_start|>system\n$text<|im_end|>",
    "[SYSTEM]$text[/SYSTEM]",
]

ZERO_WIDTH_SPACE = "\u200b"
ZERO_WIDTH_JOINER = "\u200d"
ZERO_WIDTH_NON_JOINER = "\u200c"

def case_swap(text: str) -> str:
    return "".join(
        ch.upper() if idx % 2 == 0 else ch.lower()
        for idx, ch in enumerate(text)
    )

def leetspeak(text: str) -> str:
    return "".join(_LEET_MAP.get(ch.lower(), ch) for ch in text)

def unicode_confusables(text: str) -> str:
    return "".join(_UNICODE_CONFUSABLES.get(ch.lower(), ch) for ch in text)

def whitespace_injection(text: str) -> str:
    return text.replace(" ", f" {ZERO_WIDTH_SPACE}")

def markdown_wrap(text: str) -> str:
    return f"```\n{text}\n```"

def base64_encode(text: str) -> str:
    return base64.b64encode(text.encode()).decode()

def role_prefix(text: str) -> str:
    return f"{_ROLE_PREFIXES[0]}{text}"

def instruction_tag(text: str) -> str:
    return Template(_INSTRUCTION_TAG_TEMPLATES[0]).safe_substitute(text=text)

def rot13(text: str) -> str:
    return codecs.encode(text, "rot_13")

def hex_encode(text: str) -> str:
    return text.encode().hex()

def reverse_text(text: str) -> str:
    return text[::-1]

def pig_latin(text: str) -> str:
    vowels = set("aeiouAEIOU")
    result: list[str] = []
    for word in text.split():
        if not word or not word[0].isalpha():
            result.append(word)
        elif word[0] in vowels:
            result.append(word + "way")
        else:
            i = 0
            while i < len(word) and word[i] not in vowels and word[i].isalpha():
                i += 1
            result.append(word[i:] + word[:i] + "ay")
    return " ".join(result)

def zero_width_chars(text: str) -> str:
    zwc = [ZERO_WIDTH_SPACE, ZERO_WIDTH_JOINER, ZERO_WIDTH_NON_JOINER]
    result: list[str] = []
    for idx, ch in enumerate(text):
        result.append(ch)
        if idx < len(text) - 1:
            result.append(zwc[idx % len(zwc)])
    return "".join(result)

_HOMOGLYPH_FULL: dict[str, str] = {
    "a": "\u0430",
    "b": "\u0184",
    "c": "\u0441",
    "d": "\u0501",
    "e": "\u0435",
    "f": "\u0192",
    "g": "\u0261",
    "h": "\u04bb",
    "i": "\u0456",
    "j": "\u0458",
    "k": "\u03ba",
    "l": "\u04cf",
    "m": "\u043c",
    "n": "\u0578",
    "o": "\u043e",
    "p": "\u0440",
    "q": "\u0566",
    "r": "\u0433",
    "s": "\u0455",
    "t": "\u04ad",
    "u": "\u057d",
    "v": "\u0475",
    "w": "\u051d",
    "x": "\u0445",
    "y": "\u0443",
    "z": "\u0225",
    "A": "\u0410",
    "B": "\u0412",
    "C": "\u0421",
    "D": "\u0110",
    "E": "\u0415",
    "H": "\u041d",
    "I": "\u0406",
    "K": "\u041a",
    "M": "\u041c",
    "N": "\u039d",
    "O": "\u041e",
    "P": "\u0420",
    "S": "\u0405",
    "T": "\u0422",
    "X": "\u0425",
    "Y": "\u04ae",
    "Z": "\u0396",
}

def homoglyph_full(text: str) -> str:
    return "".join(_HOMOGLYPH_FULL.get(ch, ch) for ch in text)

def payload_splitting(text: str) -> str:
    mid = len(text) // 2
    return f"{text[:mid]}\n[continue from: ]{text[mid:]}"

TRANSFORMS: dict[str, Callable[[str], str]] = {
    "case_swap": case_swap,
    "leetspeak": leetspeak,
    "unicode_confusables": unicode_confusables,
    "whitespace_injection": whitespace_injection,
    "markdown_wrap": markdown_wrap,
    "base64_encode": base64_encode,
    "role_prefix": role_prefix,
    "instruction_tag": instruction_tag,
    "rot13": rot13,
    "hex_encode": hex_encode,
    "reverse_text": reverse_text,
    "pig_latin": pig_latin,
    "zero_width_chars": zero_width_chars,
    "homoglyph_full": homoglyph_full,
    "payload_splitting": payload_splitting,
}

class MutationGenerator(BaseGenerator):

    def __init__(
        self,
        transforms: list[str] | None = None,
        include_original: bool = True,
    ) -> None:
        self.transform_names = transforms or list(TRANSFORMS.keys())
        self.include_original = include_original

    def generate(self, seeds: list[str], probe_id: str, **kwargs) -> list[TestCase]:
        cases: list[TestCase] = []
        for seed in seeds:
            if self.include_original:
                cases.append(self._make_case(probe_id, seed, "original"))
            for name in self.transform_names:
                fn = TRANSFORMS.get(name)
                if fn is None:
                    continue
                mutated = fn(seed)
                cases.append(self._make_case(probe_id, mutated, name))
        return cases

    @staticmethod
    def _make_case(probe_id: str, text: str, transform: str) -> TestCase:
        digest = hashlib.sha256(f"{probe_id}:{transform}:{text}".encode()).hexdigest()
        return TestCase(
            id=digest[:16],
            probe_id=probe_id,
            input_text=text,
            metadata={"generator": "mutation", "transform": transform},
        )
