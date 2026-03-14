
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from aegisrt.config.models import (
    ProbeConfig,
    ProviderConfig,
    ProvidersConfig,
    ReportConfig,
    RunConfig,
    TargetConfig,
)
from aegisrt.core.runner import SecurityRunner
from aegisrt.generators.adaptive import AdaptiveGenerator
from aegisrt.generators.conversation_attacker import ConversationAttacker
from aegisrt.generators.static import StaticGenerator
from aegisrt.probes.base import BaseProbe
from aegisrt.detectors.base import BaseDetector
from aegisrt.core.result import Detection, TestCase
from aegisrt.targets.base import TargetResponse


def _make_attacker_provider() -> ProviderConfig:
    return ProviderConfig(
        type="openai",
        model="gpt-4o-mini",
        api_key="sk-test-attacker-key",
        base_url="https://attacker.example.com/v1",
        params={"temperature": 0.9, "max_tokens": 2048},
    )


def _make_config(
    *,
    providers: ProvidersConfig | None = None,
) -> RunConfig:
    return RunConfig(
        target=TargetConfig(type="callback"),
        probes=[
            ProbeConfig(
                id="prompt_injection",
                family="injection",
                generator="static",
                detectors=["policy"],
            ),
        ],
        providers=providers,
    )


class _FakeDetector(BaseDetector):
    id = "fake"
    description = "fake"

    def check(self, case, response):
        return Detection(detector="fake", triggered=False, score=0.0, evidence={})


class _AdaptiveProbe(BaseProbe):

    id = "test_adaptive"
    family = "adaptive"
    severity = "high"
    description = "Test probe with AdaptiveGenerator"

    def __init__(self) -> None:
        self._generator = AdaptiveGenerator()

    def get_seeds(self) -> list[str]:
        return ["test seed"]

    def get_generator(self):
        return self._generator

    def get_detectors(self):
        return [_FakeDetector()]


class _ConversationAttackerProbe(BaseProbe):

    id = "test_conv_attack"
    family = "conversation_attack"
    severity = "high"
    description = "Test probe with ConversationAttacker"

    def __init__(self) -> None:
        self._generator = StaticGenerator()
        self.attacker = ConversationAttacker()

    def get_seeds(self) -> list[str]:
        return ["test seed"]

    def get_generator(self):
        return self._generator

    def get_detectors(self):
        return [_FakeDetector()]


class _StaticProbe(BaseProbe):

    id = "test_static"
    family = "static"
    severity = "low"
    description = "Test probe with StaticGenerator"

    def get_seeds(self) -> list[str]:
        return ["test seed"]

    def get_generator(self):
        return StaticGenerator()

    def get_detectors(self):
        return [_FakeDetector()]


class TestBuildAttackerConfig:

    def test_returns_none_when_no_providers(self):
        config = _make_config(providers=None)
        runner = SecurityRunner(config, callback_fn=lambda x: "ok")
        assert runner._build_attacker_config() is None

    def test_returns_none_when_no_attacker(self):
        config = _make_config(
            providers=ProvidersConfig(attacker=None, judge=None),
        )
        runner = SecurityRunner(config, callback_fn=lambda x: "ok")
        assert runner._build_attacker_config() is None

    def test_returns_dict_with_all_fields(self):
        attacker = _make_attacker_provider()
        config = _make_config(
            providers=ProvidersConfig(attacker=attacker),
        )
        runner = SecurityRunner(config, callback_fn=lambda x: "ok")
        result = runner._build_attacker_config()

        assert result is not None
        assert result["type"] == "openai"
        assert result["model"] == "gpt-4o-mini"
        assert result["api_key"] == "sk-test-attacker-key"
        assert result["base_url"] == "https://attacker.example.com/v1"
        assert result["temperature"] == 0.9
        assert result["max_tokens"] == 2048

    def test_defaults_base_url_when_none(self):
        attacker = ProviderConfig(
            type="openai",
            model="gpt-4o",
            api_key="sk-key",
            base_url=None,
        )
        config = _make_config(
            providers=ProvidersConfig(attacker=attacker),
        )
        runner = SecurityRunner(config, callback_fn=lambda x: "ok")
        result = runner._build_attacker_config()

        assert result["base_url"] == "https://api.openai.com/v1"

    def test_defaults_api_key_when_none(self):
        attacker = ProviderConfig(
            type="openai",
            model="gpt-4o",
            api_key=None,
        )
        config = _make_config(
            providers=ProvidersConfig(attacker=attacker),
        )
        runner = SecurityRunner(config, callback_fn=lambda x: "ok")
        result = runner._build_attacker_config()

        assert result["api_key"] == ""


class TestInjectAttackerConfig:

    def test_injects_into_adaptive_generator(self):
        attacker = _make_attacker_provider()
        config = _make_config(
            providers=ProvidersConfig(attacker=attacker),
        )
        runner = SecurityRunner(config, callback_fn=lambda x: "ok")

        probe = _AdaptiveProbe()
        assert probe._generator.attacker_config == {}

        runner._inject_attacker_config(probe)

        assert probe._generator.attacker_config["model"] == "gpt-4o-mini"
        assert probe._generator.attacker_config["api_key"] == "sk-test-attacker-key"
        assert probe._generator.attacker_config["base_url"] == "https://attacker.example.com/v1"

    def test_does_not_overwrite_existing_attacker_config(self):
        attacker = _make_attacker_provider()
        config = _make_config(
            providers=ProvidersConfig(attacker=attacker),
        )
        runner = SecurityRunner(config, callback_fn=lambda x: "ok")

        probe = _AdaptiveProbe()
        probe._generator.attacker_config = {"model": "existing-model", "api_key": "existing-key"}

        runner._inject_attacker_config(probe)

        assert probe._generator.attacker_config["model"] == "existing-model"

    def test_injects_into_conversation_attacker(self):
        attacker = _make_attacker_provider()
        config = _make_config(
            providers=ProvidersConfig(attacker=attacker),
        )
        runner = SecurityRunner(config, callback_fn=lambda x: "ok")

        probe = _ConversationAttackerProbe()
        assert probe.attacker.attacker_config == {}

        runner._inject_attacker_config(probe)

        assert probe.attacker.attacker_config["model"] == "gpt-4o-mini"
        assert probe.attacker.attacker_config["api_key"] == "sk-test-attacker-key"

    def test_no_op_when_no_attacker_provider(self):
        config = _make_config(providers=None)
        runner = SecurityRunner(config, callback_fn=lambda x: "ok")

        probe = _AdaptiveProbe()
        runner._inject_attacker_config(probe)

        assert probe._generator.attacker_config == {}

    def test_does_not_touch_static_generator(self):
        attacker = _make_attacker_provider()
        config = _make_config(
            providers=ProvidersConfig(attacker=attacker),
        )
        runner = SecurityRunner(config, callback_fn=lambda x: "ok")

        probe = _StaticProbe()
        runner._inject_attacker_config(probe)

        generator = probe.get_generator()
        assert not hasattr(generator, "attacker_config")


class TestExecuteProbeAttackerWiring:

    def test_execute_probe_injects_attacker_config(self, tmp_path):
        attacker = _make_attacker_provider()
        config = _make_config(
            providers=ProvidersConfig(attacker=attacker),
        )
        config.report = ReportConfig(output_dir=str(tmp_path / ".aegisrt"))

        runner = SecurityRunner(config, callback_fn=lambda x: "ok", no_cache=True)
        target = runner._build_target()
        target.setup()

        probe = _AdaptiveProbe()
        with patch.object(
            AdaptiveGenerator,
            "_single_shot",
            return_value=[
                TestCase(
                    id="t1",
                    probe_id="test_adaptive",
                    input_text="test prompt",
                    metadata={},
                ),
            ],
        ):
            results = runner._execute_probe(probe, target)

        assert probe._generator.attacker_config["model"] == "gpt-4o-mini"
        assert probe._generator.attacker_config["api_key"] == "sk-test-attacker-key"

        target.teardown()

    def test_execute_probe_works_without_attacker_provider(self, tmp_path):
        config = _make_config(providers=None)
        config.report = ReportConfig(output_dir=str(tmp_path / ".aegisrt"))

        runner = SecurityRunner(config, callback_fn=lambda x: "ok", no_cache=True)
        target = runner._build_target()
        target.setup()

        probe = _AdaptiveProbe()
        with patch.object(
            AdaptiveGenerator,
            "_single_shot",
            return_value=[
                TestCase(
                    id="t1",
                    probe_id="test_adaptive",
                    input_text="test prompt",
                    metadata={},
                ),
            ],
        ):
            results = runner._execute_probe(probe, target)

        assert probe._generator.attacker_config == {}
        assert len(results) > 0

        target.teardown()
