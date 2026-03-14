
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from aegisrt.targets.base import TargetResponse

logger = logging.getLogger(__name__)

class ResponseCache:

    def __init__(
        self,
        *,
        db_path: str | Path | None = None,
        default_ttl: int = 3600,
        max_size_mb: int = 100,
    ) -> None:
        self._db_path = Path(db_path) if db_path else Path(".aegisrt") / "cache.db"
        self._default_ttl = default_ttl
        self._max_size_mb = max_size_mb
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _init_db(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cache (
                prompt_hash TEXT PRIMARY KEY,
                target_hash TEXT NOT NULL,
                response_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                ttl_seconds INTEGER NOT NULL
            )
            """
        )
        self._conn.commit()

    def _make_key(self, prompt: str, target_config: dict) -> str:
        target_type = target_config.get("type", "")
        target_url = target_config.get("url", "")
        raw = f"{prompt}|{target_type}|{target_url}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def _target_hash(self, target_config: dict) -> str:
        return hashlib.sha256(
            json.dumps(target_config, sort_keys=True).encode()
        ).hexdigest()[:16]

    def get(
        self, prompt: str, target_config: dict
    ) -> TargetResponse | None:
        key = self._make_key(prompt, target_config)
        with self._lock:
            if self._conn is None:
                self._misses += 1
                return None

            row = self._conn.execute(
                "SELECT response_json, created_at, ttl_seconds FROM cache WHERE prompt_hash = ?",
                (key,),
            ).fetchone()

        if row is None:
            self._misses += 1
            return None

        response_json, created_at_str, ttl_seconds = row
        created_at = datetime.fromisoformat(created_at_str)
        now = datetime.now(timezone.utc)
        age_seconds = (now - created_at).total_seconds()

        if age_seconds > ttl_seconds:
            self._delete_key(key)
            self._misses += 1
            return None

        self._hits += 1
        try:
            data = json.loads(response_json)
            return TargetResponse(**data)
        except Exception:
            logger.warning("Failed to deserialize cached response for key %s", key)
            self._delete_key(key)
            self._misses += 1
            return None

    def put(
        self,
        prompt: str,
        target_config: dict,
        response: TargetResponse,
        ttl: int | None = None,
    ) -> None:
        key = self._make_key(prompt, target_config)
        t_hash = self._target_hash(target_config)
        if ttl is not None:
            ttl_val = ttl
        else:
            ttl_val = self._default_ttl
        now = datetime.now(timezone.utc).isoformat()
        response_json = response.model_dump_json()

        with self._lock:
            if self._conn is None:
                return
            self._conn.execute(
                """
                INSERT OR REPLACE INTO cache
                    (prompt_hash, target_hash, response_json, created_at, ttl_seconds)
                VALUES (?, ?, ?, ?, ?)
                """,
                (key, t_hash, response_json, now, ttl_val),
            )
            self._conn.commit()

        self._enforce_size_limit()

    def clear(self) -> None:
        with self._lock:
            if self._conn is None:
                return
            self._conn.execute("DELETE FROM cache")
            self._conn.commit()
        self._hits = 0
        self._misses = 0

    def stats(self) -> dict:
        entry_count = 0
        with self._lock:
            if self._conn is not None:
                row = self._conn.execute("SELECT COUNT(*) FROM cache").fetchone()
                if row:
                    entry_count = row[0]
                else:
                    entry_count = 0

        db_size_mb = 0.0
        if self._db_path.exists():
            db_size_mb = round(self._db_path.stat().st_size / (1024 * 1024), 3)

        return {
            "hits": self._hits,
            "misses": self._misses,
            "size": entry_count,
            "db_size_mb": db_size_mb,
        }

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def _delete_key(self, key: str) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.execute("DELETE FROM cache WHERE prompt_hash = ?", (key,))
                self._conn.commit()

    def _enforce_size_limit(self) -> None:
        if not self._db_path.exists():
            return
        size_mb = self._db_path.stat().st_size / (1024 * 1024)
        if size_mb <= self._max_size_mb:
            return

        with self._lock:
            if self._conn is None:
                return
            total = self._conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
            to_remove = max(1, total // 4)
            self._conn.execute(
                """
                DELETE FROM cache WHERE prompt_hash IN (
                    SELECT prompt_hash FROM cache
                    ORDER BY created_at ASC
                    LIMIT ?
                )
                """,
                (to_remove,),
            )
            self._conn.commit()
            logger.info(
                "Cache size limit exceeded (%.1f MB). Removed %d oldest entries.",
                size_mb,
                to_remove,
            )
