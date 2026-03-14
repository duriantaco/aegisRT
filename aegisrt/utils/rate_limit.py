
from __future__ import annotations

import logging
import random
import threading
import time
from typing import Any, Callable, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")

class RateLimiter:

    def __init__(self, calls_per_minute: int = 60) -> None:
        self._calls_per_minute = calls_per_minute
        self._timestamps: list[float] = []
        self._lock = threading.Lock()

    @property
    def calls_per_minute(self) -> int:
        return self._calls_per_minute

    def acquire(self) -> None:
        if self._calls_per_minute <= 0:
            return

        while True:
            delay = self.wait_time()
            if delay <= 0:
                break
            time.sleep(delay)

        with self._lock:
            self._timestamps.append(time.monotonic())

    def wait_time(self) -> float:
        if self._calls_per_minute <= 0:
            return 0.0

        with self._lock:
            now = time.monotonic()
            window = 60.0

            self._timestamps = [
                t for t in self._timestamps if now - t < window
            ]

            if len(self._timestamps) < self._calls_per_minute:
                return 0.0

            oldest = self._timestamps[0]
            return max(0.0, window - (now - oldest))

def retry_with_backoff(
    fn: Callable[..., T],
    *args: Any,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    retry_predicate: Callable[[Exception], bool] | None = None,
    **kwargs: Any,
) -> T:
    last_exc: Exception | None = None

    for attempt in range(1, max_retries + 2):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            if retry_predicate is not None and not retry_predicate(exc):
                raise
            last_exc = exc
            if attempt > max_retries:
                break
            delay = min(base_delay * (2 ** (attempt - 1)), max_delay)
            jitter = delay * (0.5 + random.random())
            logger.warning(
                "Attempt %d/%d failed (%s: %s), retrying in %.1fs",
                attempt,
                max_retries + 1,
                type(exc).__name__,
                exc,
                jitter,
            )
            time.sleep(jitter)

    raise last_exc
