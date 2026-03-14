
from __future__ import annotations

from unittest.mock import patch

import pytest

from aegisrt.core.result import TestCase
from aegisrt.generators.multilingual import (
    MultilingualGenerator,
    DEFAULT_LANGUAGES,
)
from aegisrt.plugins.entrypoints import (
    register_builtin_generators,
    register_builtin_probes,
)
from aegisrt.probes.base import BaseProbe
from aegisrt.probes.redteam.cbrn import CbrnProbe
from aegisrt.probes.redteam.cyber import CyberProbe
from aegisrt.probes.redteam.persuasion import PersuasionProbe
from aegisrt.probes.redteam.system_integrity import SystemIntegrityProbe
from aegisrt.taxonomies.harm_categories import (
    CATEGORIES,
    HarmCategory,
    HarmSubcategory,
    get_category,
    list_categories,
    list_subcategories,
)


class TestHarmTaxonomy:

    def test_all_categories_present(self):
        expected = {
            "cbrn", "cyber", "persuasion", "deception", "violence",
            "illegal_activity", "privacy", "bias", "system_integrity",
        }
        assert set(CATEGORIES.keys()) == expected

    def test_category_structure(self):
        for cat_id, cat in CATEGORIES.items():
            assert isinstance(cat, HarmCategory)
            assert cat.id == cat_id
            assert cat.name
            assert cat.description
            assert len(cat.subcategories) > 0
            for sub in cat.subcategories:
                assert isinstance(sub, HarmSubcategory)
                assert sub.id
                assert sub.name

    def test_get_category(self):
        cat = get_category("cbrn")
        assert cat is not None
        assert cat.id == "cbrn"
        assert cat.name == "Chemical, Biological, Radiological, Nuclear"

    def test_get_category_unknown(self):
        assert get_category("nonexistent") is None

    def test_list_categories(self):
        cats = list_categories()
        assert len(cats) == 9
        assert all(isinstance(c, HarmCategory) for c in cats)

    def test_list_subcategories(self):
        subs = list_subcategories("cyber")
        assert len(subs) == 4
        ids = {s.id for s in subs}
        assert "cyber_malware" in ids
        assert "cyber_exploit" in ids

    def test_list_subcategories_unknown(self):
        assert list_subcategories("nonexistent") == []

    def test_categories_are_frozen(self):
        cat = get_category("cbrn")
        with pytest.raises(AttributeError):
            cat.name = "modified"

    def test_subcategories_are_frozen(self):
        sub = list_subcategories("cbrn")[0]
        with pytest.raises(AttributeError):
            sub.name = "modified"


class TestRedTeamProbes:

    @pytest.fixture(params=[
        SystemIntegrityProbe,
        CbrnProbe,
        CyberProbe,
        PersuasionProbe,
    ])
    def probe(self, request) -> BaseProbe:
        return request.param()

    def test_probe_is_base_probe(self, probe):
        assert isinstance(probe, BaseProbe)

    def test_probe_has_id(self, probe):
        assert probe.id
        assert probe.id.startswith("rt_")

    def test_probe_has_family(self, probe):
        assert probe.family

    def test_probe_has_severity(self, probe):
        assert probe.severity in ("low", "medium", "high", "critical")

    def test_probe_has_description(self, probe):
        assert probe.description
        assert len(probe.description) > 20

    def test_probe_has_seeds(self, probe):
        seeds = probe.get_seeds()
        assert len(seeds) >= 20
        assert all(isinstance(s, str) for s in seeds)
        assert all(len(s) > 10 for s in seeds)

    def test_probe_seeds_unique(self, probe):
        seeds = probe.get_seeds()
        assert len(seeds) == len(set(seeds))

    def test_probe_has_generator(self, probe):
        gen = probe.get_generator()
        assert gen is not None

    def test_probe_has_detectors(self, probe):
        detectors = probe.get_detectors()
        assert len(detectors) >= 2

    def test_probe_generates_cases(self, probe):
        cases = probe.generate_cases()
        assert len(cases) > 0
        assert all(isinstance(c, TestCase) for c in cases)
        assert all(c.probe_id == probe.id for c in cases)

    def test_probe_has_remediation(self, probe):
        remediation = probe.remediation()
        assert len(remediation) >= 3
        assert all(isinstance(r, str) for r in remediation)

    def test_probe_detector_ids_unique(self, probe):
        detectors = probe.get_detectors()
        ids = [d.id for d in detectors]
        assert len(ids) == len(set(ids))


class TestSystemIntegrityProbe:

    def test_seeds_cover_diverse_techniques(self):
        probe = SystemIntegrityProbe()
        seeds = probe.get_seeds()
        seed_text = " ".join(seeds).lower()

        assert "dan" in seed_text
        assert "base64" in seed_text
        assert "system prompt" in seed_text
        assert "override" in seed_text
        assert "unrestricted" in seed_text

    def test_seeds_include_multiple_languages(self):
        probe = SystemIntegrityProbe()
        seeds = probe.get_seeds()

        non_ascii_seeds = [s for s in seeds if any(ord(c) > 127 for c in s)]
        assert len(non_ascii_seeds) >= 4


class TestCbrnProbe:

    def test_seeds_cover_all_domains(self):
        probe = CbrnProbe()
        seeds = probe.get_seeds()
        seed_text = " ".join(seeds).lower()

        assert "chemical" in seed_text or "nerve agent" in seed_text
        assert "biological" in seed_text or "pathogen" in seed_text
        assert "radiological" in seed_text or "radioactive" in seed_text
        assert "nuclear" in seed_text or "uranium" in seed_text


class TestCyberProbe:

    def test_seeds_cover_attack_categories(self):
        probe = CyberProbe()
        seeds = probe.get_seeds()
        seed_text = " ".join(seeds).lower()

        assert "malware" in seed_text or "keylogger" in seed_text
        assert "exploit" in seed_text
        assert "phishing" in seed_text
        assert "brute" in seed_text or "intrusion" in seed_text


class TestMultilingualGenerator:

    def test_default_languages(self):
        assert len(DEFAULT_LANGUAGES) == 15
        codes = {lang["code"] for lang in DEFAULT_LANGUAGES}
        assert "zh" in codes
        assert "ar" in codes
        assert "ru" in codes

    def test_generate_without_llm_falls_back(self):
        gen = MultilingualGenerator(
            languages=[{"code": "es", "name": "Spanish"}],
            include_code_switch=False,
            include_original=True,
        )

        with patch.object(gen, "_call_llm", return_value=None):
            cases = gen.generate(["test seed"], probe_id="test")

        assert len(cases) == 1
        assert cases[0].metadata["language"] == "en"
        assert cases[0].metadata["variant"] == "original"

    def test_generate_with_translations(self):
        gen = MultilingualGenerator(
            languages=[
                {"code": "es", "name": "Spanish"},
                {"code": "fr", "name": "French"},
            ],
            include_code_switch=False,
            include_original=True,
        )

        with patch.object(gen, "_call_llm", return_value="translated text"):
            cases = gen.generate(["seed"], probe_id="test")

        assert len(cases) == 3
        languages = {c.metadata["language"] for c in cases}
        assert languages == {"en", "es", "fr"}

    def test_generate_with_code_switch(self):
        gen = MultilingualGenerator(
            languages=[{"code": "es", "name": "Spanish"}],
            include_code_switch=True,
            include_original=True,
        )

        with patch.object(gen, "_call_llm", return_value="mixed text"):
            cases = gen.generate(["seed"], probe_id="test")

        assert len(cases) == 3
        variants = {c.metadata["variant"] for c in cases}
        assert variants == {"original", "translation", "code_switch"}

    def test_generate_without_original(self):
        gen = MultilingualGenerator(
            languages=[{"code": "es", "name": "Spanish"}],
            include_code_switch=False,
            include_original=False,
        )

        with patch.object(gen, "_call_llm", return_value="translated"):
            cases = gen.generate(["seed"], probe_id="test")

        assert len(cases) == 1
        assert cases[0].metadata["language"] == "es"

    def test_case_ids_deterministic(self):
        gen = MultilingualGenerator(
            languages=[{"code": "es", "name": "Spanish"}],
            include_code_switch=False,
        )

        with patch.object(gen, "_call_llm", return_value="hola"):
            cases1 = gen.generate(["seed"], probe_id="test")
            cases2 = gen.generate(["seed"], probe_id="test")

        assert cases1[0].id == cases2[0].id

    def test_case_metadata(self):
        gen = MultilingualGenerator(
            languages=[{"code": "de", "name": "German"}],
            include_code_switch=False,
        )

        with patch.object(gen, "_call_llm", return_value="übersetzt"):
            cases = gen.generate(["test"], probe_id="p1")

        translated = [c for c in cases if c.metadata["language"] == "de"]
        assert len(translated) == 1
        assert translated[0].metadata["generator"] == "multilingual"
        assert translated[0].metadata["variant"] == "translation"

    def test_empty_seeds(self):
        gen = MultilingualGenerator()
        with patch.object(gen, "_call_llm", return_value="x"):
            cases = gen.generate([], probe_id="test")
        assert cases == []


class TestRegistryIntegration:

    def test_red_team_probes_registered(self):
        probes = register_builtin_probes()
        assert "rt_system_integrity" in probes
        assert "rt_cbrn" in probes
        assert "rt_cyber" in probes
        assert "rt_persuasion" in probes

    def test_multilingual_generator_registered(self):
        gens = register_builtin_generators()
        assert "multilingual" in gens

    def test_total_probe_count(self):
        probes = register_builtin_probes()
        assert len(probes) >= 15

    def test_total_generator_count(self):
        gens = register_builtin_generators()
        assert len(gens) >= 9
