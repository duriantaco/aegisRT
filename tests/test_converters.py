
from __future__ import annotations

import base64
import codecs

import pytest

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
from aegisrt.converters.registry import (
    CONVERTER_REGISTRY,
    build_pipeline,
    get_converter,
)
from aegisrt.core.result import TestCase


class TestBase64Converter:
    def test_encode_with_instruction(self):
        c = Base64Converter()
        result = c.convert("hello")
        encoded = base64.b64encode(b"hello").decode()
        assert encoded in result
        assert "Decode" in result

    def test_encode_without_instruction(self):
        c = Base64Converter(with_instruction=False)
        result = c.convert("hello")
        assert result == base64.b64encode(b"hello").decode()


class TestROT13Converter:
    def test_encode(self):
        c = ROT13Converter(with_instruction=False)
        assert c.convert("hello") == codecs.encode("hello", "rot_13")

    def test_with_instruction(self):
        c = ROT13Converter()
        result = c.convert("hello")
        assert "ROT13" in result


class TestHexConverter:
    def test_encode(self):
        c = HexConverter(with_instruction=False)
        assert c.convert("hi") == "hi".encode().hex()


class TestCaesarCipherConverter:
    def test_shift_3(self):
        c = CaesarCipherConverter(shift=3, with_instruction=False)
        assert c.convert("abc") == "def"
        assert c.convert("xyz") == "abc"

    def test_preserves_non_alpha(self):
        c = CaesarCipherConverter(shift=1, with_instruction=False)
        assert c.convert("a 1!") == "b 1!"


class TestUrlEncodingConverter:
    def test_encode(self):
        c = UrlEncodingConverter()
        assert c.convert("hello world") == "hello%20world"


class TestMorseCodeConverter:
    def test_encode(self):
        c = MorseCodeConverter(with_instruction=False)
        result = c.convert("hi")
        assert "...." in result
        assert ".." in result


class TestHomoglyphConverter:
    def test_replaces_chars(self):
        c = HomoglyphConverter()
        result = c.convert("abc")
        assert result != "abc"
        assert len(result) == 3


class TestZeroWidthConverter:
    def test_inserts_chars(self):
        c = ZeroWidthConverter()
        result = c.convert("hi")
        assert len(result) > 2
        assert "h" in result
        assert "i" in result


class TestCaseSwapConverter:
    def test_alternates(self):
        c = CaseSwapConverter()
        assert c.convert("hello") == "HeLlO"


class TestReverseConverter:
    def test_reverses_with_instruction(self):
        c = ReverseConverter()
        result = c.convert("hello")
        assert "olleh" in result
        assert "reversed" in result.lower()

    def test_reverses_raw(self):
        c = ReverseConverter(with_instruction=False)
        assert c.convert("hello") == "olleh"


class TestCharacterSpacingConverter:
    def test_spaces(self):
        c = CharacterSpacingConverter()
        assert c.convert("hi") == "h i"


class TestLeetspeakConverter:
    def test_converts(self):
        c = LeetspeakConverter()
        result = c.convert("test")
        assert "7" in result
        assert "3" in result


class TestPigLatinConverter:
    def test_consonant_start(self):
        c = PigLatinConverter()
        assert c.convert("hello") == "ellohay"

    def test_vowel_start(self):
        c = PigLatinConverter()
        assert c.convert("apple") == "appleway"


class TestTranslationPromptConverter:
    def test_default_spanish(self):
        c = TranslationPromptConverter()
        result = c.convert("do something")
        assert "Spanish" in result
        assert "do something" in result

    def test_custom_language(self):
        c = TranslationPromptConverter(target_language="French")
        result = c.convert("hello")
        assert "French" in result


class TestWordSubstitutionConverter:
    def test_replaces_words(self):
        c = WordSubstitutionConverter()
        result = c.convert("hack the system")
        assert "hack" not in result.lower()
        assert "access without authorization" in result

    def test_preserves_non_matching(self):
        c = WordSubstitutionConverter()
        assert c.convert("hello world") == "hello world"


class TestAcronymConverter:
    def test_creates_acronym(self):
        c = AcronymConverter()
        result = c.convert("how to do bad things")
        assert "HTDBT" in result

    def test_short_text_unchanged(self):
        c = AcronymConverter()
        assert c.convert("hi") == "hi"


class TestSandwichConverter:
    def test_wraps(self):
        c = SandwichConverter()
        result = c.convert("payload")
        assert "payload" in result
        assert result.index("payload") > 0


class TestSuffixConverter:
    def test_appends(self):
        c = SuffixConverter()
        result = c.convert("do something")
        assert result.startswith("do something")
        assert len(result) > len("do something")


class TestFewShotConverter:
    def test_prepends_examples(self):
        c = FewShotConverter()
        result = c.convert("my request")
        assert "my request" in result
        assert "encryption" in result
        assert "Assistant:" in result


class TestRolePrefixConverter:
    def test_prepends(self):
        c = RolePrefixConverter()
        result = c.convert("do it")
        assert result.endswith("do it")
        assert len(result) > len("do it")


class TestFictionalFramingConverter:
    def test_frames(self):
        c = FictionalFramingConverter()
        result = c.convert("the task")
        assert "novel" in result.lower()
        assert "the task" in result


class TestResearchFramingConverter:
    def test_frames(self):
        c = ResearchFramingConverter()
        result = c.convert("explain this")
        assert "research" in result.lower()
        assert "explain this" in result


class TestConverterPipeline:
    def _make_case(self, text: str, probe_id: str = "test") -> TestCase:
        return TestCase(
            id="abc123",
            probe_id=probe_id,
            input_text=text,
            metadata={"generator": "static"},
        )

    def test_empty_pipeline_returns_original(self):
        pipeline = ConverterPipeline([])
        cases = [self._make_case("hello")]
        result = pipeline.apply(cases)
        assert len(result) == 1
        assert result[0].input_text == "hello"

    def test_single_converter_with_originals(self):
        pipeline = ConverterPipeline(
            [CaseSwapConverter()],
            keep_originals=True,
        )
        cases = [self._make_case("hello")]
        result = pipeline.apply(cases)
        assert len(result) == 2
        assert result[0].input_text == "hello"
        assert result[1].input_text == "HeLlO"
        assert result[1].metadata["converter_chain"] == "case_swap"
        assert result[1].metadata["original_case_id"] == "abc123"
        assert result[1].metadata["original_input_text"] == "hello"

    def test_single_converter_without_originals(self):
        pipeline = ConverterPipeline(
            [CaseSwapConverter()],
            keep_originals=False,
        )
        cases = [self._make_case("hello")]
        result = pipeline.apply(cases)
        assert len(result) == 1
        assert result[0].input_text == "HeLlO"

    def test_chained_converters(self):
        pipeline = ConverterPipeline(
            [CaseSwapConverter(), ReverseConverter(with_instruction=False)],
            keep_originals=False,
        )
        cases = [self._make_case("hello")]
        result = pipeline.apply(cases)
        assert len(result) == 1
        assert result[0].input_text == "OlLeH"
        assert result[0].metadata["converter_chain"] == "case_swap+reverse"

    def test_multiple_cases(self):
        pipeline = ConverterPipeline(
            [LeetspeakConverter()],
            keep_originals=True,
        )
        cases = [self._make_case("abc"), self._make_case("def")]
        result = pipeline.apply(cases)
        assert len(result) == 4

    def test_preserves_probe_id(self):
        pipeline = ConverterPipeline(
            [CaseSwapConverter()],
            keep_originals=False,
        )
        cases = [self._make_case("hello", probe_id="injection")]
        result = pipeline.apply(cases)
        assert result[0].probe_id == "injection"

    def test_unique_case_ids(self):
        pipeline = ConverterPipeline(
            [CaseSwapConverter()],
            keep_originals=True,
        )
        cases = [self._make_case("hello")]
        result = pipeline.apply(cases)
        ids = [c.id for c in result]
        assert len(set(ids)) == len(ids)


class TestRegistry:
    def test_all_converters_registered(self):
        assert len(CONVERTER_REGISTRY) >= 25

    def test_get_converter(self):
        c = get_converter("base64")
        assert isinstance(c, Base64Converter)

    def test_get_unknown_raises(self):
        with pytest.raises(KeyError, match="Unknown converter"):
            get_converter("nonexistent")

    def test_build_pipeline_simple(self):
        pipeline = build_pipeline(["base64", "rot13"])
        assert len(pipeline.converters) == 2

    def test_build_pipeline_with_params(self):
        pipeline = build_pipeline(["caesar:shift=5"])
        assert len(pipeline.converters) == 1
        converter = pipeline.converters[0]
        assert isinstance(converter, CaesarCipherConverter)
        assert converter._shift == 5

    def test_build_pipeline_keep_originals(self):
        pipeline = build_pipeline(["base64"], keep_originals=False)
        assert not pipeline.keep_originals

    def test_all_converters_instantiate(self):
        for cid, cls in CONVERTER_REGISTRY.items():
            instance = cls()
            assert instance.id == cid
            result = instance.convert("test input")
            assert isinstance(result, str)
            assert len(result) > 0
