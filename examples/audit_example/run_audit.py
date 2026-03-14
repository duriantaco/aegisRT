# ruff: noqa: E402

"""Run AegisRT's static audit scanner against the vulnerable example app.

Usage:
    python examples/audit_example/run_audit.py

This script programmatically invokes the same analysis that
``aegisrt audit examples/audit_example/vulnerable_app.py`` performs,
but does so from Python so you can integrate audit results into your
own tooling.
"""

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from aegisrt.audit.python_ast import parse_file
from aegisrt.audit.rules import ALL_RULES


def main() -> None:
    target = Path(__file__).parent / "vulnerable_app.py"
    print(f"Auditing: {target}\n")

    tree = parse_file(target)
    if tree is None:
        print("Failed to parse the file.")
        return

    findings = []
    for rule in ALL_RULES:
        findings.extend(rule.match(tree, str(target)))

    if not findings:
        print("No findings -- the app looks clean (unexpected for this example!).")
        return

    for f in sorted(findings, key=lambda x: x.line):
        print(f"  [{f.severity.upper():8s}]  {f.rule_id}  line {f.line:>3d}  {f.message}")
        print(f"             Remediation: {f.remediation}")
        print()

    severity_counts: dict[str, int] = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    print(f"Total findings: {len(findings)}")
    for sev in ("critical", "high", "medium", "low"):
        count = severity_counts.get(sev, 0)
        if count:
            print(f"  {sev.upper():8s}: {count}")


if __name__ == "__main__":
    main()
