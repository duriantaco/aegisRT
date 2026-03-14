from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from aegisrt.core.result import TestCase
from aegisrt.generators.base import BaseGenerator

class DatasetGenerator(BaseGenerator):

    def __init__(
        self,
        path: str,
        format: str = "auto",
        column_map: dict[str, str] | None = None,
    ) -> None:
        if path.startswith("builtin://"):
            from aegisrt.datasets.registry import resolve_dataset_path
            self.path = resolve_dataset_path(path)
        else:
            self.path = Path(path)
        self.format = format
        self.column_map = column_map or {}

    def generate(self, seeds: list[str], probe_id: str, **kwargs) -> list[TestCase]:
        records = self._load_records()
        cases: list[TestCase] = []
        for record in records:
            prompt = record.get("prompt", "")
            if not prompt:
                continue
            expected = record.get("expected", "")
            metadata = record.get("metadata", {})
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except (json.JSONDecodeError, TypeError):
                    metadata = {"raw_metadata": metadata}

            case_id = self._make_id(probe_id, prompt)
            extra_meta: dict = {
                "generator": "dataset",
                "source": str(self.path),
            }
            if expected:
                extra_meta["expected"] = expected
            if metadata:
                extra_meta.update(metadata)

            cases.append(
                TestCase(
                    id=case_id,
                    probe_id=probe_id,
                    input_text=prompt,
                    metadata=extra_meta,
                )
            )
        return cases

    def _detect_format(self) -> str:
        suffix = self.path.suffix.lower()
        if suffix == ".csv":
            return "csv"
        if suffix == ".jsonl":
            return "jsonl"
        if suffix == ".json":
            return "json"
        raise ValueError(
            f"Cannot auto-detect format for '{self.path}'. "
            "Specify format='csv', 'json', or 'jsonl'."
        )

    def _apply_column_map(self, record: dict) -> dict:
        if not self.column_map:
            return record
        mapped: dict = {}
        reverse_map = {v: k for k, v in self.column_map.items()}
        for key, value in record.items():
            canonical = reverse_map.get(key, key)
            mapped[canonical] = value
        return mapped

    def _load_records(self) -> list[dict]:
        if self.format != "auto":
            fmt = self.format
        else:
            fmt = self._detect_format()

        if fmt == "csv":
            return self._load_csv()
        if fmt == "json":
            return self._load_json()
        if fmt == "jsonl":
            return self._load_jsonl()
        raise ValueError(f"Unsupported format: {fmt}")

    def _load_csv(self) -> list[dict]:
        records: list[dict] = []
        with open(self.path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                records.append(self._apply_column_map(dict(row)))
        return records

    def _load_json(self) -> list[dict]:
        with open(self.path, encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, list):
            raise ValueError("JSON file must contain a top-level array of objects.")
        return [self._apply_column_map(item) for item in data]

    def _load_jsonl(self) -> list[dict]:
        records: list[dict] = []
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                records.append(self._apply_column_map(json.loads(line)))
        return records

    @staticmethod
    def _make_id(probe_id: str, text: str) -> str:
        digest = hashlib.sha256(f"{probe_id}:dataset:{text}".encode()).hexdigest()
        return digest[:16]
