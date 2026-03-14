
from __future__ import annotations

import hashlib
import json

def hash_case(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]

def hash_config(config: dict) -> str:
    canonical = json.dumps(config, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
