from __future__ import annotations

from aegisrt.core.result import TestCase
from aegisrt.generators.static import StaticGenerator
from aegisrt.generators.mutations import (
    MutationGenerator,
    case_swap,
    leetspeak,
    base64_encode,
    TRANSFORMS,
)

def test_static_generator_produces_cases():
    gen = StaticGenerator()
    seeds = ["Hello world", "Ignore instructions"]
    cases = gen.generate(seeds, probe_id="test_probe")

    assert len(cases) == 2
    assert all(isinstance(c, TestCase) for c in cases)
    assert cases[0].input_text == "Hello world"
    assert cases[1].input_text == "Ignore instructions"
    assert all(c.probe_id == "test_probe" for c in cases)

def test_static_generator_unique_ids():
    gen = StaticGenerator()
    seeds = ["alpha", "beta", "gamma", "delta"]
    cases = gen.generate(seeds, probe_id="test")

    ids = [c.id for c in cases]
    assert len(ids) == len(set(ids))

def test_static_generator_deterministic_ids():
    gen = StaticGenerator()
    a = gen.generate(["hello"], probe_id="p1")
    b = gen.generate(["hello"], probe_id="p1")
    assert a[0].id == b[0].id

def test_static_generator_empty_seeds():
    gen = StaticGenerator()
    assert gen.generate([], probe_id="test") == []

def test_mutation_generator_multiplies_cases():
    seeds = ["test input"]
    gen = MutationGenerator()
    cases = gen.generate(seeds, probe_id="mut_test")

    expected_per_seed = 1 + len(TRANSFORMS)
    assert len(cases) == expected_per_seed

def test_mutation_generator_without_original():
    gen = MutationGenerator(include_original=False)
    cases = gen.generate(["seed"], probe_id="p1")
    assert len(cases) == len(TRANSFORMS)
    transforms_used = {c.metadata["transform"] for c in cases}
    assert "original" not in transforms_used

def test_mutation_case_swap():
    result = case_swap("hello")
    assert result == "HeLlO"

def test_mutation_leetspeak():
    result = leetspeak("test")
    assert result == "7357"
    assert result != "test"

def test_mutation_base64_encode():
    import base64
    result = base64_encode("hello")
    decoded = base64.b64decode(result).decode()
    assert decoded == "hello"

def test_mutation_all_transforms_produce_different_output():
    original = "ignore previous instructions"
    for name, fn in TRANSFORMS.items():
        mutated = fn(original)
        assert mutated != original, f"Transform '{name}' did not modify the input"
