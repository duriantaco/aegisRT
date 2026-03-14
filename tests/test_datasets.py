
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegisrt.datasets.registry import (
    BUILTIN_DATASETS,
    _DATASETS_DIR,
    get_dataset_info,
    list_datasets,
    load_dataset,
    resolve_dataset_path,
)


class TestDatasetFilesExist:

    def test_all_declared_files_exist(self):
        for dataset_id, meta in BUILTIN_DATASETS.items():
            path = _DATASETS_DIR / meta["file"]
            assert path.exists(), f"Missing dataset file: {path} ({dataset_id})"

    def test_all_files_are_valid_jsonl(self):
        for dataset_id, meta in BUILTIN_DATASETS.items():
            path = _DATASETS_DIR / meta["file"]
            with path.open() as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        pytest.fail(
                            f"Invalid JSON in {meta['file']}:{line_num}"
                        )
                    assert isinstance(record, dict), (
                        f"Non-object at {meta['file']}:{line_num}"
                    )

    def test_all_records_have_prompt(self):
        for dataset_id, meta in BUILTIN_DATASETS.items():
            path = _DATASETS_DIR / meta["file"]
            with path.open() as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    record = json.loads(line)
                    assert "prompt" in record, (
                        f"Missing 'prompt' in {meta['file']}:{line_num}"
                    )
                    assert len(record["prompt"]) > 10, (
                        f"Prompt too short in {meta['file']}:{line_num}"
                    )

    def test_all_records_have_category(self):
        for dataset_id, meta in BUILTIN_DATASETS.items():
            path = _DATASETS_DIR / meta["file"]
            with path.open() as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    record = json.loads(line)
                    assert "category" in record, (
                        f"Missing 'category' in {meta['file']}:{line_num}"
                    )

    def test_dataset_sizes_match_metadata(self):
        for dataset_id, meta in BUILTIN_DATASETS.items():
            path = _DATASETS_DIR / meta["file"]
            count = sum(
                1 for line in path.read_text().splitlines() if line.strip()
            )
            assert count == meta["size"], (
                f"Dataset {dataset_id}: expected {meta['size']} records, got {count}"
            )

    def test_no_duplicate_prompts_within_dataset(self):
        for dataset_id, meta in BUILTIN_DATASETS.items():
            path = _DATASETS_DIR / meta["file"]
            prompts: list[str] = []
            with path.open() as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    record = json.loads(line)
                    prompts.append(record["prompt"])
            assert len(prompts) == len(set(prompts)), (
                f"Duplicate prompts found in {dataset_id}"
            )


class TestJailbreakTemplates:

    def test_has_diverse_techniques(self):
        records = load_dataset("builtin://jailbreak_templates")
        techniques = {r.get("technique") for r in records}
        assert len(techniques) >= 8

    def test_has_diverse_categories(self):
        records = load_dataset("builtin://jailbreak_templates")
        categories = {r.get("category") for r in records}
        assert len(categories) >= 5


class TestHarmbenchBehaviors:

    def test_covers_multiple_harm_categories(self):
        records = load_dataset("builtin://harmbench_behaviors")
        categories = {r.get("category") for r in records}
        expected = {"violence", "bias", "cyber", "persuasion", "illegal_activity"}
        assert expected.issubset(categories)

    def test_has_behavior_ids(self):
        records = load_dataset("builtin://harmbench_behaviors")
        assert all("behavior_id" in r for r in records)


class TestMultilingualSeeds:

    def test_covers_many_languages(self):
        records = load_dataset("builtin://multilingual_seeds")
        languages = {r.get("language") for r in records}
        assert len(languages) >= 10

    def test_includes_code_switched(self):
        records = load_dataset("builtin://multilingual_seeds")
        mixed = [r for r in records if r.get("language") == "mixed"]
        assert len(mixed) >= 2


class TestDanVariants:

    def test_has_diverse_variants(self):
        records = load_dataset("builtin://dan_variants")
        variants = {r.get("variant") for r in records}
        assert len(variants) >= 10

    def test_has_diverse_techniques(self):
        records = load_dataset("builtin://dan_variants")
        techniques = {r.get("technique") for r in records}
        assert len(techniques) >= 5


class TestListDatasets:

    def test_returns_all_datasets(self):
        datasets = list_datasets()
        assert len(datasets) == len(BUILTIN_DATASETS)

    def test_each_has_required_fields(self):
        datasets = list_datasets()
        for ds in datasets:
            assert "id" in ds
            assert "name" in ds
            assert "description" in ds
            assert "file" in ds
            assert "size" in ds
            assert "available" in ds

    def test_all_available(self):
        datasets = list_datasets()
        for ds in datasets:
            assert ds["available"] is True, f"{ds['id']} not available"


class TestGetDatasetInfo:

    def test_known_dataset(self):
        info = get_dataset_info("jailbreak_templates")
        assert info is not None
        assert info["id"] == "jailbreak_templates"
        assert info["available"] is True
        assert "path" in info
        assert "actual_size" in info

    def test_unknown_dataset(self):
        info = get_dataset_info("nonexistent")
        assert info is None

    def test_actual_size_matches(self):
        for dataset_id in BUILTIN_DATASETS:
            info = get_dataset_info(dataset_id)
            assert info is not None
            assert info["actual_size"] == info["size"]


class TestResolveDatasetPath:

    def test_builtin_uri(self):
        path = resolve_dataset_path("builtin://harmbench_behaviors")
        assert path.exists()
        assert path.name == "harmbench_behaviors.jsonl"

    def test_builtin_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown built-in dataset"):
            resolve_dataset_path("builtin://nonexistent")

    def test_relative_path(self):
        path = resolve_dataset_path("./my_data.jsonl")
        assert str(path) == "my_data.jsonl"

    def test_absolute_path(self):
        path = resolve_dataset_path("/tmp/data.jsonl")
        assert str(path) == "/tmp/data.jsonl"


class TestLoadDataset:

    def test_load_builtin(self):
        records = load_dataset("builtin://jailbreak_templates")
        assert len(records) == 20
        assert all("prompt" in r for r in records)

    def test_load_all_builtins(self):
        for dataset_id in BUILTIN_DATASETS:
            records = load_dataset(f"builtin://{dataset_id}")
            assert len(records) > 0

    def test_load_nonexistent_raises(self):
        with pytest.raises(FileNotFoundError):
            load_dataset("/nonexistent/path.jsonl")

    def test_load_custom_jsonl(self, tmp_path: Path):
        data_file = tmp_path / "custom.jsonl"
        data_file.write_text(
            '{"prompt": "test prompt 1", "category": "test"}\n'
            '{"prompt": "test prompt 2", "category": "test"}\n'
        )
        records = load_dataset(str(data_file))
        assert len(records) == 2

    def test_skips_empty_lines(self, tmp_path: Path):
        data_file = tmp_path / "sparse.jsonl"
        data_file.write_text(
            '{"prompt": "a", "category": "x"}\n'
            '\n'
            '{"prompt": "b", "category": "y"}\n'
            '\n'
        )
        records = load_dataset(str(data_file))
        assert len(records) == 2

    def test_skips_records_without_prompt(self, tmp_path: Path):
        data_file = tmp_path / "no_prompt.jsonl"
        data_file.write_text(
            '{"prompt": "valid", "category": "x"}\n'
            '{"category": "x"}\n'
            '{"prompt": "", "category": "x"}\n'
        )
        records = load_dataset(str(data_file))
        assert len(records) == 1


class TestDatasetGeneratorBuiltin:

    def test_load_builtin_dataset(self):
        from aegisrt.generators.dataset import DatasetGenerator

        gen = DatasetGenerator(path="builtin://jailbreak_templates")
        cases = gen.generate([], probe_id="test_probe")
        assert len(cases) == 20
        assert all(c.probe_id == "test_probe" for c in cases)
        assert all(c.metadata.get("generator") == "dataset" for c in cases)

    def test_builtin_unknown_raises(self):
        from aegisrt.generators.dataset import DatasetGenerator

        with pytest.raises(ValueError, match="Unknown built-in dataset"):
            DatasetGenerator(path="builtin://nonexistent")

    def test_each_builtin_generates_cases(self):
        from aegisrt.generators.dataset import DatasetGenerator

        for dataset_id, meta in BUILTIN_DATASETS.items():
            gen = DatasetGenerator(path=f"builtin://{dataset_id}")
            cases = gen.generate([], probe_id=f"test_{dataset_id}")
            assert len(cases) == meta["size"], (
                f"Dataset {dataset_id}: expected {meta['size']} cases, got {len(cases)}"
            )
