
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

class ArtifactManager:

    def __init__(self, base_dir: str | Path = ".aegisrt/artifacts") -> None:
        self._base = Path(base_dir)

    def _run_dir(self, run_id: str) -> Path:
        d = self._base / run_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def save_artifact(self, run_id: str, name: str, data: Any) -> Path:
        dest = self._run_dir(run_id) / name
        if isinstance(data, bytes):
            dest.write_bytes(data)
        elif isinstance(data, str):
            dest.write_text(data, encoding="utf-8")
        else:
            dest.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return dest.resolve()

    def load_artifact(self, run_id: str, name: str) -> str | bytes | None:
        path = self._base / run_id / name
        if not path.exists():
            return None
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return path.read_bytes()

    def list_artifacts(self, run_id: str) -> list[str]:
        run_dir = self._base / run_id
        if not run_dir.is_dir():
            return []
        return sorted(f.name for f in run_dir.iterdir() if f.is_file())
