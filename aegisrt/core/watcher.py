from __future__ import annotations

import time
from pathlib import Path
from typing import Callable

from rich.console import Console

console = Console()


class ConfigWatcher:

    def __init__(
        self,
        config_path: str,
        callback: Callable[[], None],
        poll_interval: float = 2.0,
    ) -> None:
        self._path = Path(config_path)
        self._callback = callback
        self._interval = poll_interval
        self._last_mtime: float = 0

    def start(self) -> None:
        console.print(
            f"[cyan]Watching {self._path} for changes... (Ctrl+C to stop)[/cyan]"
        )
        self._last_mtime = self._path.stat().st_mtime
        try:
            while True:
                current_mtime = self._path.stat().st_mtime
                if current_mtime != self._last_mtime:
                    self._last_mtime = current_mtime
                    console.print(
                        f"\n[yellow]Config changed, re-running...[/yellow]"
                    )
                    self._callback()
                time.sleep(self._interval)
        except KeyboardInterrupt:
            console.print("\n[cyan]Watch mode stopped.[/cyan]")
