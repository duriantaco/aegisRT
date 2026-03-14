from __future__ import annotations

import subprocess
import time

from aegisrt.config.models import TargetConfig
from aegisrt.targets.base import BaseTarget, TargetResponse

_PROMPT_PLACEHOLDER = "{{prompt}}"

class SubprocessTarget(BaseTarget):

    def __init__(self, config: TargetConfig) -> None:
        params = config.params or {}
        self._command_template: str = params.get("command", "")
        if not self._command_template:
            raise ValueError(
                "SubprocessTarget requires a 'command' in target.params, "
                "e.g. params: { command: 'echo {{prompt}}' }"
            )
        self._timeout = int(params.get("timeout", config.timeout_seconds))
        self._cwd: str | None = params.get("cwd")
        self._use_shell = params.get("shell", "true").lower() in ("true", "1", "yes")

    def execute(self, prompt: str) -> TargetResponse:
        use_stdin = _PROMPT_PLACEHOLDER not in self._command_template
        command = self._command_template.replace(_PROMPT_PLACEHOLDER, prompt)

        start = time.perf_counter()
        try:
            result = subprocess.run(
                command if self._use_shell else command.split(),
                shell=self._use_shell,
                input=prompt if use_stdin else None,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                cwd=self._cwd,
            )
            elapsed_ms = (time.perf_counter() - start) * 1000

            stdout = result.stdout.strip()
            stderr = result.stderr.strip()

            if result.returncode != 0 and not stdout:
                text = f"[ERROR] Process exited with code {result.returncode}: {stderr}"
            else:
                text = stdout

            return TargetResponse(
                text=text,
                raw={
                    "stdout": stdout,
                    "stderr": stderr,
                    "returncode": result.returncode,
                },
                latency_ms=elapsed_ms,
                metadata={
                    "returncode": result.returncode,
                    "command": command if not use_stdin else self._command_template,
                },
            )
        except subprocess.TimeoutExpired:
            elapsed_ms = (time.perf_counter() - start) * 1000
            return TargetResponse(
                text=f"[ERROR] Command timed out after {self._timeout}s",
                raw={"error": "timeout"},
                latency_ms=elapsed_ms,
                metadata={"error": True, "timeout": True},
            )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            return TargetResponse(
                text=f"[ERROR] {type(exc).__name__}: {exc}",
                raw=str(exc),
                latency_ms=elapsed_ms,
                metadata={"error": True},
            )
