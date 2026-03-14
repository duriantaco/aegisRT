from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

from aegisrt.config.models import BenchmarkConfig, RunConfig

_ENV_VAR_PATTERN = re.compile(r"\$\{([^}]+)\}")


def expand_env_vars(data: Any) -> Any:
    if isinstance(data, str):
        def _replace(match: re.Match) -> str:
            var_name = match.group(1)
            return os.environ.get(var_name, match.group(0))
        return _ENV_VAR_PATTERN.sub(_replace, data)
    elif isinstance(data, dict):
        return {k: expand_env_vars(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [expand_env_vars(item) for item in data]
    return data


def load_config(path: str | Path) -> RunConfig:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    raw_text = config_path.read_text(encoding="utf-8")
    raw_data = yaml.safe_load(raw_text)

    if raw_data is None:
        raise ValueError(f"Config file is empty: {config_path}")

    expanded = expand_env_vars(raw_data)
    return RunConfig.model_validate(expanded)


def load_benchmark_config(path: str | Path) -> BenchmarkConfig:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    raw_text = config_path.read_text(encoding="utf-8")
    raw_data = yaml.safe_load(raw_text)

    if raw_data is None:
        raise ValueError(f"Config file is empty: {config_path}")

    expanded = expand_env_vars(raw_data)
    return BenchmarkConfig.model_validate(expanded)
