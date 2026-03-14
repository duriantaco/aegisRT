from __future__ import annotations

from pydantic import BaseModel, Field

from aegisrt.core.result import RunReport, TestResult

class RunDiff(BaseModel):

    base_run_id: str
    compare_run_id: str
    new_failures: list[TestResult] = Field(default_factory=list)
    resolved: list[TestResult] = Field(default_factory=list)
    persistent_failures: list[TestResult] = Field(default_factory=list)
    persistent_passes: list[TestResult] = Field(default_factory=list)
    new_passes: list[TestResult] = Field(default_factory=list)
    skipped: list[TestResult] = Field(default_factory=list)
    regressions: int = 0
    improvements: int = 0
    summary: dict = Field(default_factory=dict)

def _result_key(result: TestResult) -> str:
    return f"{result.probe_id}:{result.case_id}"


def _is_skipped(result: TestResult | None) -> bool:
    return bool(result and result.evidence.get("skipped"))


def _effective_counts(results: list[TestResult]) -> dict[str, int | float]:
    skipped = sum(1 for result in results if _is_skipped(result))
    passed = sum(1 for result in results if result.passed and not _is_skipped(result))
    failed = sum(1 for result in results if not result.passed)
    executable_total = passed + failed
    return {
        "total": len(results),
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "pass_rate": round(passed / executable_total, 4) if executable_total else 1.0,
    }

def compare_runs(base: RunReport, compare: RunReport) -> RunDiff:
    base_map: dict[str, TestResult] = {}
    for r in base.results:
        base_map[_result_key(r)] = r

    compare_map: dict[str, TestResult] = {}
    for r in compare.results:
        compare_map[_result_key(r)] = r

    new_failures: list[TestResult] = []
    resolved: list[TestResult] = []
    persistent_failures: list[TestResult] = []
    persistent_passes: list[TestResult] = []
    new_passes: list[TestResult] = []
    skipped: list[TestResult] = []

    all_keys = set(base_map.keys()) | set(compare_map.keys())

    for key in sorted(all_keys):
        base_result = base_map.get(key)
        compare_result = compare_map.get(key)

        if _is_skipped(compare_result):
            skipped.append(compare_result)
            continue
        if _is_skipped(base_result):
            base_result = None

        if base_result is not None and compare_result is not None:
            if not base_result.passed and not compare_result.passed:
                persistent_failures.append(compare_result)
            elif base_result.passed and not compare_result.passed:
                new_failures.append(compare_result)
            elif not base_result.passed and compare_result.passed:
                resolved.append(compare_result)
            else:
                persistent_passes.append(compare_result)
        elif base_result is None and compare_result is not None:
            if compare_result.passed:
                new_passes.append(compare_result)
            else:
                new_failures.append(compare_result)
        elif base_result is not None and compare_result is None:
            if not base_result.passed:
                resolved.append(base_result)

    regressions = len(new_failures)
    improvements = len(resolved)

    base_counts = _effective_counts(base.results)
    compare_counts = _effective_counts(compare.results)

    summary = {
        "base_total": base_counts["total"],
        "base_passed": base_counts["passed"],
        "base_failed": base_counts["failed"],
        "base_skipped": base_counts["skipped"],
        "base_pass_rate": base_counts["pass_rate"],
        "compare_total": compare_counts["total"],
        "compare_passed": compare_counts["passed"],
        "compare_failed": compare_counts["failed"],
        "compare_skipped": compare_counts["skipped"],
        "compare_pass_rate": compare_counts["pass_rate"],
        "regressions": regressions,
        "improvements": improvements,
        "persistent_failures": len(persistent_failures),
        "persistent_passes": len(persistent_passes),
        "new_passes": len(new_passes),
        "skipped": len(skipped),
    }

    return RunDiff(
        base_run_id=base.run_id,
        compare_run_id=compare.run_id,
        new_failures=new_failures,
        resolved=resolved,
        persistent_failures=persistent_failures,
        persistent_passes=persistent_passes,
        new_passes=new_passes,
        skipped=skipped,
        regressions=regressions,
        improvements=improvements,
        summary=summary,
    )

def format_diff_summary(diff: RunDiff) -> str:
    s = diff.summary
    lines = [
        f"Diff: {diff.base_run_id} -> {diff.compare_run_id}",
        "",
        f"Base run:    {s['base_total']} total, {s['base_passed']} passed, "
        f"{s['base_failed']} failed, {s['base_skipped']} skipped "
        f"({s['base_pass_rate'] * 100:.1f}% pass rate)",
        f"Compare run: {s['compare_total']} total, {s['compare_passed']} passed, "
        f"{s['compare_failed']} failed, {s['compare_skipped']} skipped "
        f"({s['compare_pass_rate'] * 100:.1f}% pass rate)",
        "",
        f"Regressions (new failures):  {diff.regressions}",
        f"Improvements (resolved):     {diff.improvements}",
        f"Persistent failures:         {len(diff.persistent_failures)}",
        f"Persistent passes:           {len(diff.persistent_passes)}",
        f"New passes:                  {len(diff.new_passes)}",
        f"Skipped in compare run:      {len(diff.skipped)}",
    ]
    return "\n".join(lines)
