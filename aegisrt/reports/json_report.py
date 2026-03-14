from __future__ import annotations

import json
from pathlib import Path

from aegisrt.core.result import RunReport


class JsonReportWriter:

    def write(self, report: RunReport, path: str | Path) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        data = report.model_dump(mode="json")
        out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return out.resolve()
