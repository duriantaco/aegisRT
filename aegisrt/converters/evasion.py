
from __future__ import annotations

from aegisrt.converters.base import BaseConverter

_HOMOGLYPHS: dict[str, str] = {
    "a": "\u0430", "b": "\u0184", "c": "\u0441", "d": "\u0501",
    "e": "\u0435", "f": "\u0192", "g": "\u0261", "h": "\u04bb",
    "i": "\u0456", "j": "\u0458", "k": "\u03ba", "l": "\u04cf",
    "m": "\u043c", "n": "\u0578", "o": "\u043e", "p": "\u0440",
    "q": "\u0566", "r": "\u0433", "s": "\u0455", "t": "\u04ad",
    "u": "\u057d", "v": "\u0475", "w": "\u051d", "x": "\u0445",
    "y": "\u0443", "z": "\u0225",
    "A": "\u0410", "B": "\u0412", "C": "\u0421", "D": "\u0110",
    "E": "\u0415", "H": "\u041d", "I": "\u0406", "K": "\u041a",
    "M": "\u041c", "N": "\u039d", "O": "\u041e", "P": "\u0420",
    "S": "\u0405", "T": "\u0422", "X": "\u0425", "Y": "\u04ae",
    "Z": "\u0396",
}

ZERO_WIDTH_SPACE = "\u200b"
ZERO_WIDTH_JOINER = "\u200d"
ZERO_WIDTH_NON_JOINER = "\u200c"

_UNICODE_CONFUSABLES: dict[str, str] = {
    "a": "\u0430", "c": "\u0441", "e": "\u0435", "o": "\u043e",
    "p": "\u0440", "s": "\u0455", "x": "\u0445", "y": "\u0443",
    "i": "\u0456", "d": "\u0501",
}


class HomoglyphConverter(BaseConverter):

    id = "homoglyph"
    description = "Replace characters with Unicode homoglyphs"

    def convert(self, text: str) -> str:
        return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


class UnicodeConfusableConverter(BaseConverter):

    id = "unicode_confusable"
    description = "Replace common letters with Cyrillic lookalikes"

    def convert(self, text: str) -> str:
        return "".join(_UNICODE_CONFUSABLES.get(ch.lower(), ch) for ch in text)


class ZeroWidthConverter(BaseConverter):

    id = "zero_width"
    description = "Insert zero-width characters between letters"

    def convert(self, text: str) -> str:
        zwc = [ZERO_WIDTH_SPACE, ZERO_WIDTH_JOINER, ZERO_WIDTH_NON_JOINER]
        result: list[str] = []
        for idx, ch in enumerate(text):
            result.append(ch)
            if idx < len(text) - 1:
                result.append(zwc[idx % len(zwc)])
        return "".join(result)


class WhitespaceConverter(BaseConverter):

    id = "whitespace"
    description = "Replace spaces with zero-width spaces"

    def convert(self, text: str) -> str:
        return text.replace(" ", f" {ZERO_WIDTH_SPACE}")


class CaseSwapConverter(BaseConverter):

    id = "case_swap"
    description = "Alternate character casing"

    def convert(self, text: str) -> str:
        return "".join(
            ch.upper() if idx % 2 == 0 else ch.lower()
            for idx, ch in enumerate(text)
        )


class ReverseConverter(BaseConverter):

    id = "reverse"
    description = "Reverse the text with decode instruction"

    def __init__(self, *, with_instruction: bool = True) -> None:
        self._with_instruction = with_instruction

    def convert(self, text: str) -> str:
        reversed_text = text[::-1]
        if self._with_instruction:
            return (
                "The following text is reversed. Read it backwards and "
                f"follow the instructions: {reversed_text}"
            )
        return reversed_text


class CharacterSpacingConverter(BaseConverter):

    id = "char_spacing"
    description = "Insert spaces between characters"

    def convert(self, text: str) -> str:
        return " ".join(text)
