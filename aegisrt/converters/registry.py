
from __future__ import annotations

from aegisrt.converters.base import BaseConverter, ConverterPipeline
from aegisrt.converters.encoding import (
    Base64Converter,
    CaesarCipherConverter,
    HexConverter,
    MorseCodeConverter,
    ROT13Converter,
    UrlEncodingConverter,
)
from aegisrt.converters.evasion import (
    CaseSwapConverter,
    CharacterSpacingConverter,
    HomoglyphConverter,
    ReverseConverter,
    UnicodeConfusableConverter,
    WhitespaceConverter,
    ZeroWidthConverter,
)
from aegisrt.converters.injection import (
    FewShotConverter,
    FictionalFramingConverter,
    InstructionTagConverter,
    MarkdownWrapConverter,
    PayloadSplitConverter,
    ResearchFramingConverter,
    RolePrefixConverter,
    SandwichConverter,
    SuffixConverter,
)
from aegisrt.converters.linguistic import (
    AcronymConverter,
    LeetspeakConverter,
    PigLatinConverter,
    RephraseConverter,
    TranslationPromptConverter,
    WordSubstitutionConverter,
)
from aegisrt.plugins.loader import load_plugins

CONVERTER_REGISTRY: dict[str, type[BaseConverter]] = {
    "base64": Base64Converter,
    "rot13": ROT13Converter,
    "hex": HexConverter,
    "caesar": CaesarCipherConverter,
    "url_encode": UrlEncodingConverter,
    "morse": MorseCodeConverter,
    "homoglyph": HomoglyphConverter,
    "unicode_confusable": UnicodeConfusableConverter,
    "zero_width": ZeroWidthConverter,
    "whitespace": WhitespaceConverter,
    "case_swap": CaseSwapConverter,
    "reverse": ReverseConverter,
    "char_spacing": CharacterSpacingConverter,
    "leetspeak": LeetspeakConverter,
    "pig_latin": PigLatinConverter,
    "translation": TranslationPromptConverter,
    "rephrase": RephraseConverter,
    "word_substitution": WordSubstitutionConverter,
    "acronym": AcronymConverter,
    "sandwich": SandwichConverter,
    "suffix": SuffixConverter,
    "few_shot": FewShotConverter,
    "role_prefix": RolePrefixConverter,
    "instruction_tag": InstructionTagConverter,
    "markdown_wrap": MarkdownWrapConverter,
    "payload_split": PayloadSplitConverter,
    "fictional": FictionalFramingConverter,
    "research": ResearchFramingConverter,
}

_PLUGIN_CONVERTER_REGISTRY: dict[str, type[BaseConverter]] | None = None


def _get_converter_registry() -> dict[str, type[BaseConverter]]:
    global _PLUGIN_CONVERTER_REGISTRY
    if _PLUGIN_CONVERTER_REGISTRY is None:
        _PLUGIN_CONVERTER_REGISTRY = dict(CONVERTER_REGISTRY)
        _PLUGIN_CONVERTER_REGISTRY.update(load_plugins("aegisrt.converters"))
    return _PLUGIN_CONVERTER_REGISTRY


def get_converter(converter_id: str, **kwargs) -> BaseConverter:
    registry = _get_converter_registry()
    cls = registry.get(converter_id)
    if cls is None:
        available = ", ".join(sorted(registry.keys()))
        raise KeyError(
            f"Unknown converter '{converter_id}'. "
            f"Available converters: {available}"
        )
    return cls(**kwargs)


def build_pipeline(
    converter_ids: list[str],
    *,
    keep_originals: bool = True,
) -> ConverterPipeline:
    converters: list[BaseConverter] = []
    for spec in converter_ids:
        parts = spec.split(":")
        converter_id = parts[0]
        kwargs: dict = {}
        for part in parts[1:]:
            if "=" in part:
                key, val = part.split("=", 1)
                try:
                    kwargs[key] = int(val)
                except ValueError:
                    try:
                        kwargs[key] = float(val)
                    except ValueError:
                        kwargs[key] = val
        converters.append(get_converter(converter_id, **kwargs))

    return ConverterPipeline(converters, keep_originals=keep_originals)
