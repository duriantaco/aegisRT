
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from aegisrt.core.result import RunReport, TestResult

_SCHEMA_SQL = """\
CREATE TABLE IF NOT EXISTS runs (
    run_id      TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    target_info_json TEXT NOT NULL DEFAULT '{}',
    config_json TEXT NOT NULL DEFAULT '{}',
    summary_json TEXT NOT NULL DEFAULT '{}',
    metrics_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS results (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id           TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    case_id          TEXT NOT NULL,
    probe_id         TEXT NOT NULL,
    input_text       TEXT NOT NULL DEFAULT '',
    response_text    TEXT NOT NULL DEFAULT '',
    passed           INTEGER NOT NULL,
    score            REAL NOT NULL,
    severity         TEXT NOT NULL,
    confidence       REAL NOT NULL,
    evidence_json    TEXT NOT NULL DEFAULT '{}',
    remediation_json TEXT NOT NULL DEFAULT '[]',
    trace_json       TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS triage (
    finding_key TEXT PRIMARY KEY,
    probe_id    TEXT NOT NULL,
    case_id     TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'new',
    owner       TEXT NOT NULL DEFAULT '',
    note        TEXT NOT NULL DEFAULT '',
    first_seen  TEXT,
    last_seen   TEXT,
    updated_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_results_run_id ON results(run_id);
CREATE INDEX IF NOT EXISTS idx_triage_status ON triage(status);
"""

_RUN_COLUMN_DEFS = {
    "target_info_json": "TEXT NOT NULL DEFAULT '{}'",
    "metrics_json": "TEXT NOT NULL DEFAULT '{}'",
}

_RESULT_COLUMN_DEFS = {
    "input_text": "TEXT NOT NULL DEFAULT ''",
    "response_text": "TEXT NOT NULL DEFAULT ''",
    "trace_json": "TEXT NOT NULL DEFAULT '{}'",
}

TRIAGE_STATUSES = (
    "new",
    "acknowledged",
    "fixed",
    "accepted_risk",
    "false_positive",
)


def make_finding_key(probe_id: str, case_id: str) -> str:
    return f"{probe_id}:{case_id}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

class ResultStore:

    def __init__(self, db_path: str | Path = ".aegisrt/results.db") -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self._db_path))
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def init_db(self) -> None:
        self.conn.executescript(_SCHEMA_SQL)
        self._ensure_columns("runs", _RUN_COLUMN_DEFS)
        self._ensure_columns("results", _RESULT_COLUMN_DEFS)
        self.conn.commit()

    def _ensure_columns(self, table: str, columns: dict[str, str]) -> None:
        existing = {
            row["name"]
            for row in self.conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        for name, ddl in columns.items():
            if name not in existing:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")

    def save_run(self, report: RunReport) -> None:
        self.init_db()
        cur = self.conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO runs "
            "(run_id, timestamp, target_info_json, config_json, summary_json, metrics_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                report.run_id,
                report.timestamp,
                json.dumps(report.target_info, default=str),
                json.dumps(report.config, default=str),
                json.dumps(report.summary, default=str),
                json.dumps(report.metrics, default=str),
            ),
        )
        cur.execute("DELETE FROM results WHERE run_id = ?", (report.run_id,))
        for r in report.results:
            cur.execute(
                "INSERT INTO results "
                "(run_id, case_id, probe_id, input_text, response_text, passed, score, "
                "severity, confidence, evidence_json, remediation_json, trace_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    report.run_id,
                    r.case_id,
                    r.probe_id,
                    r.input_text,
                    r.response_text,
                    int(r.passed),
                    r.score,
                    r.severity,
                    r.confidence,
                    json.dumps(r.evidence, default=str),
                    json.dumps(r.remediation, default=str),
                    json.dumps(r.trace, default=str),
                ),
            )
            if not r.passed and not r.evidence.get("skipped"):
                self._touch_triage_finding(
                    probe_id=r.probe_id,
                    case_id=r.case_id,
                    observed_at=report.timestamp,
                )
        self.conn.commit()

    def load_run(self, run_id: str) -> RunReport | None:
        self.init_db()
        row = self.conn.execute(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if row is None:
            return None

        result_rows = self.conn.execute(
            "SELECT * FROM results WHERE run_id = ? ORDER BY id", (run_id,)
        ).fetchall()

        results = [
            TestResult(
                case_id=rr["case_id"],
                probe_id=rr["probe_id"],
                input_text=rr["input_text"] if "input_text" in rr.keys() else "",
                response_text=rr["response_text"] if "response_text" in rr.keys() else "",
                passed=bool(rr["passed"]),
                score=rr["score"],
                severity=rr["severity"],
                confidence=rr["confidence"],
                evidence=json.loads(rr["evidence_json"]),
                remediation=json.loads(rr["remediation_json"]),
                trace=json.loads(rr["trace_json"])
                if "trace_json" in rr.keys() and rr["trace_json"]
                else {},
            )
            for rr in result_rows
        ]

        return RunReport(
            run_id=row["run_id"],
            timestamp=row["timestamp"],
            target_info=json.loads(row["target_info_json"])
            if "target_info_json" in row.keys() and row["target_info_json"]
            else {},
            config=json.loads(row["config_json"]),
            summary=json.loads(row["summary_json"]),
            results=results,
            metrics=json.loads(row["metrics_json"])
            if "metrics_json" in row.keys() and row["metrics_json"]
            else {},
        )

    def list_runs(self) -> list[dict]:
        self.init_db()
        rows = self.conn.execute(
            "SELECT run_id, timestamp, summary_json FROM runs ORDER BY timestamp DESC"
        ).fetchall()
        return [
            {
                "run_id": r["run_id"],
                "timestamp": r["timestamp"],
                "summary": json.loads(r["summary_json"]),
            }
            for r in rows
        ]

    def delete_run(self, run_id: str) -> bool:
        self.init_db()
        cur = self.conn.execute("DELETE FROM runs WHERE run_id = ?", (run_id,))
        self.conn.commit()
        return cur.rowcount > 0

    def get_triage(self, probe_id: str, case_id: str) -> dict | None:
        self.init_db()
        row = self.conn.execute(
            "SELECT * FROM triage WHERE finding_key = ?",
            (make_finding_key(probe_id, case_id),),
        ).fetchone()
        if row is None:
            return None
        return self._triage_row_to_dict(row)

    def get_triage_map(self, results: Iterable[TestResult]) -> dict[str, dict]:
        self.init_db()
        finding_keys = list(
            {
                make_finding_key(result.probe_id, result.case_id)
                for result in results
            }
        )
        if not finding_keys:
            return {}
        placeholders = ",".join("?" for _ in finding_keys)
        rows = self.conn.execute(
            f"SELECT * FROM triage WHERE finding_key IN ({placeholders})",
            finding_keys,
        ).fetchall()
        return {
            row["finding_key"]: self._triage_row_to_dict(row)
            for row in rows
        }

    def upsert_triage(
        self,
        *,
        probe_id: str,
        case_id: str,
        status: str,
        owner: str = "",
        note: str = "",
    ) -> dict:
        self.init_db()
        updated_at = _utc_now()
        self.conn.execute(
            "INSERT INTO triage "
            "(finding_key, probe_id, case_id, status, owner, note, first_seen, last_seen, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?) "
            "ON CONFLICT(finding_key) DO UPDATE SET "
            "probe_id = excluded.probe_id, "
            "case_id = excluded.case_id, "
            "status = excluded.status, "
            "owner = excluded.owner, "
            "note = excluded.note, "
            "updated_at = excluded.updated_at",
            (
                make_finding_key(probe_id, case_id),
                probe_id,
                case_id,
                status,
                owner,
                note,
                updated_at,
            ),
        )
        self.conn.commit()
        triage = self.get_triage(probe_id, case_id)
        if triage is None:
            raise RuntimeError("triage update was not persisted")
        return triage

    def _touch_triage_finding(
        self,
        *,
        probe_id: str,
        case_id: str,
        observed_at: str,
    ) -> None:
        self.conn.execute(
            "INSERT INTO triage "
            "(finding_key, probe_id, case_id, status, owner, note, first_seen, last_seen, updated_at) "
            "VALUES (?, ?, ?, 'new', '', '', ?, ?, ?) "
            "ON CONFLICT(finding_key) DO UPDATE SET "
            "probe_id = excluded.probe_id, "
            "case_id = excluded.case_id, "
            "last_seen = excluded.last_seen, "
            "updated_at = excluded.updated_at",
            (
                make_finding_key(probe_id, case_id),
                probe_id,
                case_id,
                observed_at,
                observed_at,
                observed_at,
            ),
        )

    def _triage_row_to_dict(self, row: sqlite3.Row) -> dict:
        return {
            "finding_key": row["finding_key"],
            "probe_id": row["probe_id"],
            "case_id": row["case_id"],
            "status": row["status"],
            "owner": row["owner"],
            "note": row["note"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "updated_at": row["updated_at"],
        }

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
