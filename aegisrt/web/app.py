
from __future__ import annotations

import asyncio
import json
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from aegisrt import __version__
from aegisrt.core.result import RunReport
from aegisrt.core.trace_sessions import get_trace_session_id
from aegisrt.storage.sqlite import TRIAGE_STATUSES, ResultStore, make_finding_key

_STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(
    title="AegisRT",
    description="LLM Security Testing Dashboard",
    version=__version__,
)

app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

def _get_store() -> ResultStore:
    return ResultStore()


class TriageUpdateRequest(BaseModel):
    probe_id: str
    case_id: str
    status: str
    owner: str = ""
    note: str = ""


def _serialize_results(
    store: ResultStore, results: list[Any]
) -> list[dict[str, Any]]:
    triage_map = store.get_triage_map(results)
    payload: list[dict[str, Any]] = []
    for result in results:
        item = result.model_dump(mode="json")
        finding_key = make_finding_key(result.probe_id, result.case_id)
        item["finding_key"] = finding_key
        item["triage"] = triage_map.get(finding_key)
        payload.append(item)
    return payload


def _severity_rank(severity: str) -> int:
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }.get(str(severity).lower(), 0)


def _is_closed_triage(result: dict[str, Any]) -> bool:
    triage = result.get("triage") or {}
    return triage.get("status") in {"fixed", "false_positive"}


def _build_attack_sessions(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sessions: dict[str, dict[str, Any]] = {}

    for result in results:
        trace = result.get("trace") or {}
        session_fallback = (
            result.get("finding_key")
            if isinstance(trace.get("steps"), list) and trace.get("steps")
            else None
        )
        session_id = get_trace_session_id(trace, fallback=session_fallback)
        if session_id is None:
            continue

        attack_id = trace.get("attack_id") or session_id
        steps = trace.get("steps") if isinstance(trace.get("steps"), list) else []
        session = sessions.setdefault(
            session_id,
            {
                "session_id": session_id,
                "attack_id": attack_id,
                "result_count": 0,
                "finding_count": 0,
                "open_findings": 0,
                "highest_severity": "low",
                "highest_score": 0.0,
                "participants": set(),
                "tool_names": set(),
                "memory_stores": set(),
                "trust_boundaries": set(),
                "step_count": 0,
                "steps": [],
                "finding_keys": [],
                "representative_finding_key": None,
                "representative_probe_id": None,
                "representative_case_id": None,
            },
        )

        session["result_count"] += 1
        if not result.get("passed") and not result.get("evidence", {}).get("skipped"):
            session["finding_count"] += 1
            session["finding_keys"].append(result.get("finding_key"))
            if not _is_closed_triage(result):
                session["open_findings"] += 1

            if (
                session["representative_finding_key"] is None
                or _severity_rank(result.get("severity", "low"))
                > _severity_rank(session["highest_severity"])
                or (
                    result.get("severity") == session["highest_severity"]
                    and result.get("score", 0.0) > session["highest_score"]
                )
            ):
                session["representative_finding_key"] = result.get("finding_key")
                session["representative_probe_id"] = result.get("probe_id")
                session["representative_case_id"] = result.get("case_id")

        if _severity_rank(result.get("severity", "low")) > _severity_rank(
            session["highest_severity"]
        ):
            session["highest_severity"] = result.get("severity", "low")
        session["highest_score"] = max(session["highest_score"], result.get("score", 0.0))

        if len(steps) > session["step_count"]:
            session["step_count"] = len(steps)
            session["steps"] = steps

        for step in steps:
            if not isinstance(step, dict):
                continue
            participant = step.get("agent_id") or step.get("agent_role")
            if participant:
                session["participants"].add(str(participant))
            if step.get("tool_name"):
                session["tool_names"].add(str(step["tool_name"]))
            if step.get("memory_store"):
                session["memory_stores"].add(str(step["memory_store"]))
            if step.get("trust_boundary"):
                session["trust_boundaries"].add(str(step["trust_boundary"]))

    ordered = []
    for session in sessions.values():
        session["participants"] = sorted(session["participants"])
        session["tool_names"] = sorted(session["tool_names"])
        session["memory_stores"] = sorted(session["memory_stores"])
        session["trust_boundaries"] = sorted(session["trust_boundaries"])
        session["cross_boundary"] = len(session["trust_boundaries"]) > 0
        ordered.append(session)

    ordered.sort(
        key=lambda item: (
            _severity_rank(item["highest_severity"]),
            item["open_findings"],
            item["finding_count"],
            item["step_count"],
        ),
        reverse=True,
    )
    return ordered

@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

@app.get("/api/runs")
def list_runs() -> list[dict[str, Any]]:
    store = _get_store()
    try:
        runs = store.list_runs()
        enriched = []
        for run in runs:
            summary = run.get("summary", {})
            enriched.append(
                {
                    "run_id": run["run_id"],
                    "timestamp": run["timestamp"],
                    "total": summary.get("total", 0),
                    "passed": summary.get("passed", 0),
                    "failed": summary.get("failed", 0),
                    "summary": summary,
                }
            )
        return enriched
    finally:
        store.close()

@app.get("/api/runs/{run_id}")
def get_run(run_id: str) -> dict[str, Any]:
    store = _get_store()
    try:
        report = store.load_run(run_id)
        if report is None:
            raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
        results = _serialize_results(store, report.results)
        return {
            "run_id": report.run_id,
            "timestamp": report.timestamp,
            "target_info": report.target_info,
            "config": report.config,
            "results": results,
            "attack_sessions": _build_attack_sessions(results),
            "summary": report.summary,
            "metrics": report.metrics,
        }
    finally:
        store.close()

@app.get("/api/runs/{run_id}/results")
def get_run_results(
    run_id: str,
    severity: str | None = Query(None),
    passed: bool | None = Query(None),
    probe_id: str | None = Query(None),
) -> list[dict[str, Any]]:
    store = _get_store()
    try:
        report = store.load_run(run_id)
        if report is None:
            raise HTTPException(status_code=404, detail=f"Run {run_id} not found")

        results = report.results

        if severity is not None:
            results = [r for r in results if r.severity.lower() == severity.lower()]
        if passed is not None:
            results = [r for r in results if r.passed == passed]
        if probe_id is not None:
            results = [r for r in results if r.probe_id == probe_id]

        return _serialize_results(store, results)
    finally:
        store.close()


@app.put("/api/triage")
def update_triage(update: TriageUpdateRequest) -> dict[str, Any]:
    status = update.status.strip().lower()
    if status not in TRIAGE_STATUSES:
        valid = ", ".join(TRIAGE_STATUSES)
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported triage status '{update.status}'. Expected one of: {valid}",
        )

    store = _get_store()
    try:
        return store.upsert_triage(
            probe_id=update.probe_id,
            case_id=update.case_id,
            status=status,
            owner=update.owner.strip(),
            note=update.note.strip(),
        )
    finally:
        store.close()

@app.delete("/api/runs/{run_id}")
def delete_run(run_id: str) -> dict[str, Any]:
    store = _get_store()
    try:
        deleted = store.delete_run(run_id)
        if not deleted:
            raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
        return {"deleted": True, "run_id": run_id}
    finally:
        store.close()

_active_runs: dict[str, dict[str, Any]] = {}

@app.post("/api/runs")
async def start_run(request: Request) -> dict[str, Any]:
    body = await request.json()
    run_id = f"run-{uuid.uuid4().hex[:12]}"

    _active_runs[run_id] = {"status": "queued", "started_at": datetime.now(timezone.utc).isoformat()}

    asyncio.create_task(_execute_run(run_id, body))

    return {"run_id": run_id, "status": "started"}

async def _execute_run(run_id: str, config_body: dict[str, Any]) -> None:
    _active_runs[run_id]["status"] = "running"
    try:
        config_path = config_body.get("config_path")
        if config_path:
            from aegisrt.config.loader import load_config
            from aegisrt.core.runner import SecurityRunner

            cfg = load_config(config_path)
            runner = SecurityRunner(cfg, run_id=run_id)
            report = await asyncio.to_thread(runner.run)
        else:
            report = RunReport(
                run_id=run_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                summary={"error": "No config_path provided in request body"},
            )

            store = _get_store()
            try:
                store.save_run(report)
            finally:
                store.close()

        _active_runs[run_id]["status"] = "complete"
        _active_runs[run_id]["stored_run_id"] = report.run_id
    except Exception as exc:
        _active_runs[run_id]["status"] = "failed"
        _active_runs[run_id]["error"] = str(exc)

@app.get("/api/runs/{run_id1}/diff/{run_id2}")
def diff_runs(run_id1: str, run_id2: str) -> dict[str, Any]:
    from aegisrt.core.diff import compare_runs

    store = _get_store()
    try:
        base = store.load_run(run_id1)
        if base is None:
            raise HTTPException(status_code=404, detail=f"Base run {run_id1} not found")

        compare = store.load_run(run_id2)
        if compare is None:
            raise HTTPException(
                status_code=404, detail=f"Compare run {run_id2} not found"
            )

        run_diff = compare_runs(base, compare)
        return run_diff.model_dump(mode="json")
    finally:
        store.close()

@app.get("/api/history")
def get_history() -> list[dict[str, Any]]:
    store = _get_store()
    try:
        runs = store.list_runs()
        if not runs:
            return []

        runs_chrono = list(reversed(runs))
        prev_pass_rate: float | None = None
        results: list[dict[str, Any]] = []

        for run in runs_chrono:
            summary = run.get("summary", {})
            total = summary.get("total", 0)
            passed = summary.get("passed", 0)
            failed = summary.get("failed", 0)
            pass_rate = summary.get("pass_rate", 1.0 if total == 0 else 0.0)

            if prev_pass_rate is not None:
                if pass_rate > prev_pass_rate:
                    trend = "up"
                elif pass_rate < prev_pass_rate:
                    trend = "down"
                else:
                    trend = "same"
            else:
                trend = "baseline"

            prev_pass_rate = pass_rate

            results.append({
                "run_id": run["run_id"],
                "timestamp": run["timestamp"],
                "total": total,
                "passed": passed,
                "failed": failed,
                "pass_rate": pass_rate,
                "trend": trend,
            })

        results.reverse()
        return results
    finally:
        store.close()

@app.get("/api/runs/{run_id}/report/{fmt}")
def get_report(run_id: str, fmt: str) -> Response:
    store = _get_store()
    try:
        report = store.load_run(run_id)
        if report is None:
            raise HTTPException(status_code=404, detail=f"Run {run_id} not found")

        if fmt == "json":
            from aegisrt.reports.json_report import JsonReportWriter

            tmp = Path(tempfile.mktemp(suffix=".json"))
            JsonReportWriter().write(report, tmp)
            content = tmp.read_text(encoding="utf-8")
            tmp.unlink(missing_ok=True)
            return JSONResponse(content=json.loads(content))

        elif fmt == "html":
            from aegisrt.reports.html_report import HtmlReportWriter

            tmp = Path(tempfile.mktemp(suffix=".html"))
            HtmlReportWriter().write(report, tmp)
            content = tmp.read_text(encoding="utf-8")
            tmp.unlink(missing_ok=True)
            return HTMLResponse(content=content)

        elif fmt == "sarif":
            from aegisrt.reports.sarif_report import SarifReportWriter

            tmp = Path(tempfile.mktemp(suffix=".sarif.json"))
            SarifReportWriter().write(report, tmp)
            content = tmp.read_text(encoding="utf-8")
            tmp.unlink(missing_ok=True)
            return JSONResponse(content=json.loads(content))

        elif fmt == "junit":
            from aegisrt.reports.junit_report import JunitReportWriter

            tmp = Path(tempfile.mktemp(suffix=".xml"))
            JunitReportWriter().write(report, tmp)
            content = tmp.read_text(encoding="utf-8")
            tmp.unlink(missing_ok=True)
            return Response(content=content, media_type="application/xml")

        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported format: {fmt}. Use json, html, sarif, or junit.",
            )
    finally:
        store.close()

@app.get("/api/probes")
def list_probes() -> list[dict[str, Any]]:
    from aegisrt.plugins.entrypoints import register_builtin_probes
    from aegisrt.plugins.loader import load_plugins

    registry = register_builtin_probes()
    registry.update(load_plugins("aegisrt.probes"))

    result = []
    for _, cls in sorted(registry.items()):
        probe = cls()
        try:
            seed_count = len(probe.get_seeds())
        except Exception:
            seed_count = 0
        result.append(
            {
                "id": probe.id,
                "family": probe.family,
                "severity": probe.severity,
                "description": probe.description,
                "seed_count": seed_count,
            }
        )
    return result

@app.get("/api/suites")
def list_suites() -> list[dict[str, Any]]:
    from aegisrt.suites.builtins import get_builtin_suites

    suites = get_builtin_suites()
    return [
        {
            "name": s.name,
            "description": s.description,
            "probe_count": len(s.probes),
            "probes": [
                {"id": p.id, "family": p.family, "severity": p.severity}
                for p in s.probes
            ],
        }
        for s in suites
    ]

@app.get("/")
async def serve_index() -> FileResponse:
    return FileResponse(str(_STATIC_DIR / "index.html"))

@app.get("/favicon.svg")
async def serve_favicon() -> FileResponse:
    return FileResponse(str(_STATIC_DIR / "favicon.svg"), media_type="image/svg+xml")

@app.get("/{path:path}")
async def catch_all(path: str) -> FileResponse:
    static_path = _STATIC_DIR / path
    if static_path.is_file():
        return FileResponse(str(static_path))
    return FileResponse(str(_STATIC_DIR / "index.html"))
