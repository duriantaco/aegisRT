
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DATASETS_DIR = Path(__file__).parent


BUILTIN_DATASETS: dict[str, dict[str, Any]] = {
    "jailbreak_templates": {
        "name": "Jailbreak Templates",
        "description": (
            "20 curated jailbreak prompt templates covering instruction override, "
            "persona hijacking, encoding tricks, fiction framing, authority claims, "
            "logic inversion, and emotional manipulation."
        ),
        "file": "jailbreak_templates.jsonl",
        "size": 20,
        "categories": [
            "instruction_override",
            "persona_hijack",
            "encoding",
            "fiction_framing",
            "authority_claim",
            "logic_inversion",
            "emotional_manipulation",
            "code_framing",
            "hypothetical",
        ],
        "source": "AegisRT curated",
        "license": "Apache-2.0",
    },
    "harmbench_behaviors": {
        "name": "HarmBench Behaviors",
        "description": (
            "25 harmful behavior prompts spanning violence, bias, cyber, "
            "persuasion, illegal activity, privacy, CBRN, and deception. "
            "Inspired by the HarmBench benchmark standard behaviors."
        ),
        "file": "harmbench_behaviors.jsonl",
        "size": 25,
        "categories": [
            "violence",
            "bias",
            "cyber",
            "persuasion",
            "illegal_activity",
            "privacy",
            "cbrn",
            "deception",
        ],
        "source": "Inspired by HarmBench (Mazeika et al., 2024)",
        "license": "Apache-2.0",
    },
    "advbench_subset": {
        "name": "AdvBench Subset",
        "description": (
            "20 adversarial behavior prompts covering cyber attacks, "
            "illegal activity, deception, privacy violations, and propaganda. "
            "Inspired by the AdvBench harmful behaviors dataset."
        ),
        "file": "advbench_subset.jsonl",
        "size": 20,
        "categories": [
            "cyber",
            "illegal_activity",
            "deception",
            "privacy",
            "persuasion",
            "cbrn",
        ],
        "source": "Inspired by AdvBench (Zou et al., 2023)",
        "license": "Apache-2.0",
    },
    "dan_variants": {
        "name": "DAN Jailbreak Variants",
        "description": (
            "15 DAN-style jailbreak variants including DAN, STAN, DUDE, AIM, "
            "BetterDAN, Developer Mode, dual-persona, and other persona-based "
            "jailbreak techniques."
        ),
        "file": "dan_variants.jsonl",
        "size": 15,
        "categories": ["system_integrity"],
        "source": "AegisRT curated from public jailbreak research",
        "license": "Apache-2.0",
    },
    "multilingual_seeds": {
        "name": "Multilingual Attack Seeds",
        "description": (
            "18 attack seeds in 15 languages plus code-switched variants. "
            "Tests cross-language safety robustness with instruction override "
            "and mode-switching prompts."
        ),
        "file": "multilingual_seeds.jsonl",
        "size": 18,
        "categories": ["system_integrity"],
        "languages": [
            "zh", "ar", "ru", "ja", "ko", "hi", "de", "pt", "tr",
            "vi", "th", "sw", "uk", "es", "fr", "mixed",
        ],
        "source": "AegisRT curated",
        "license": "Apache-2.0",
    },
}


def list_datasets() -> list[dict[str, Any]]:
    result = []
    for dataset_id, meta in BUILTIN_DATASETS.items():
        entry = {"id": dataset_id, **meta}
        path = _DATASETS_DIR / meta["file"]
        entry["available"] = path.exists()
        result.append(entry)
    return result


def get_dataset_info(dataset_id: str) -> dict[str, Any] | None:
    meta = BUILTIN_DATASETS.get(dataset_id)
    if meta is None:
        return None
    entry = {"id": dataset_id, **meta}
    path = _DATASETS_DIR / meta["file"]
    entry["available"] = path.exists()
    entry["path"] = str(path)
    if path.exists():
        entry["actual_size"] = sum(1 for line in path.read_text().splitlines() if line.strip())
    return entry


def resolve_dataset_path(uri: str) -> Path:
    if uri.startswith("builtin://"):
        dataset_id = uri[len("builtin://"):]
        meta = BUILTIN_DATASETS.get(dataset_id)
        if meta is None:
            raise ValueError(
                f"Unknown built-in dataset: '{dataset_id}'. "
                f"Available: {', '.join(BUILTIN_DATASETS.keys())}"
            )
        path = _DATASETS_DIR / meta["file"]
        if not path.exists():
            raise FileNotFoundError(f"Built-in dataset file missing: {path}")
        return path

    return Path(uri)


def load_dataset(uri: str) -> list[dict[str, Any]]:
    path = resolve_dataset_path(uri)
    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found: {path}")

    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                if isinstance(record, dict) and record.get("prompt"):
                    records.append(record)
            except json.JSONDecodeError:
                logger.warning(
                    "Skipping invalid JSON at %s:%d", path, line_num
                )

    return records
