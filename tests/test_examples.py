
from __future__ import annotations

import importlib
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

def _run_script(script_path: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / script_path)],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )

def test_audit_example_runs_as_documented(tmp_path):
    result = _run_script("examples/audit_example/run_audit.py", tmp_path)

    assert result.returncode == 0, result.stderr
    assert "Total findings:" in result.stdout

def test_callback_example_runs_as_documented(tmp_path):
    result = _run_script("examples/callback_basic/run.py", tmp_path)

    assert result.returncode == 0, result.stderr
    assert "Results:" in result.stdout
    assert (tmp_path / ".aegisrt").exists()

def test_callback_example_import_has_no_side_effects(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sys.modules.pop("examples.callback_basic.run", None)
    importlib.invalidate_caches()

    module = importlib.import_module("examples.callback_basic.run")

    assert callable(module.main)
    assert not (tmp_path / ".aegisrt").exists()


def test_agent_callback_example_runs_as_documented(tmp_path):
    result = _run_script("examples/callback_basic/agent_run.py", tmp_path)

    assert result.returncode == 0, result.stderr
    assert "Agent trace:" in result.stdout
    assert (tmp_path / ".aegisrt").exists()
