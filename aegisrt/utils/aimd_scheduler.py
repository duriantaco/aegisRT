
from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Callable, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")
R = TypeVar("R")


class RateLimitHit(Exception):

    def __init__(self, retry_after: float = 0.0) -> None:
        self.retry_after = retry_after
        super().__init__(f"Rate limited, retry after {retry_after}s")


class AimdScheduler:

    def __init__(
        self,
        max_concurrency: int = 8,
        min_concurrency: int = 1,
        increase_threshold: int = 10,
        decrease_factor: float = 0.5,
        min_delay_ms: float = 0.0,
    ) -> None:
        self._max = max_concurrency
        self._min = min_concurrency
        self._current = max_concurrency
        self._increase_threshold = increase_threshold
        self._decrease_factor = decrease_factor
        self._min_delay = min_delay_ms / 1000.0

        self._consecutive_successes = 0
        self._lock = threading.Lock()
        self._last_request_time = 0.0

    @property
    def current_concurrency(self) -> int:
        with self._lock:
            return self._current

    def on_success(self) -> None:
        with self._lock:
            self._consecutive_successes += 1
            if self._consecutive_successes >= self._increase_threshold:
                old = self._current
                self._current = min(self._current + 1, self._max)
                self._consecutive_successes = 0
                if self._current != old:
                    logger.debug(
                        "AIMD: concurrency increased %d -> %d",
                        old, self._current,
                    )

    def on_rate_limit(self, retry_after: float = 0.0) -> float:
        with self._lock:
            old = self._current
            self._current = max(
                int(self._current * self._decrease_factor), self._min
            )
            self._consecutive_successes = 0
            logger.warning(
                "AIMD: rate limit hit, concurrency decreased %d -> %d",
                old, self._current,
            )
            return max(retry_after, 1.0)

    def wait_for_slot(self) -> None:
        if self._min_delay <= 0:
            return
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request_time
            if elapsed < self._min_delay:
                time.sleep(self._min_delay - elapsed)
            self._last_request_time = time.monotonic()


def run_with_aimd(
    fn: Callable[[T], R],
    items: list[T],
    max_concurrency: int = 8,
    min_delay_ms: float = 0.0,
) -> list[R]:
    if not items:
        return []

    scheduler = AimdScheduler(
        max_concurrency=max_concurrency,
        min_delay_ms=min_delay_ms,
    )
    results: list[R | None] = [None] * len(items)
    remaining: list[tuple[int, T]] = list(enumerate(items))

    while remaining:
        batch_size = scheduler.current_concurrency
        batch = remaining[:batch_size]
        remaining = remaining[batch_size:]

        retry_items: list[tuple[int, T]] = []

        with ThreadPoolExecutor(max_workers=batch_size) as pool:
            future_to_idx: dict[Future, tuple[int, T]] = {}
            for idx, item in batch:
                scheduler.wait_for_slot()
                future_to_idx[pool.submit(fn, item)] = (idx, item)

            for future in as_completed(future_to_idx):
                idx, item = future_to_idx[future]
                try:
                    results[idx] = future.result()
                    scheduler.on_success()
                except RateLimitHit as exc:
                    wait = scheduler.on_rate_limit(exc.retry_after)
                    time.sleep(wait)
                    retry_items.append((idx, item))
                except Exception:
                    raise

        remaining = retry_items + remaining

    return results
