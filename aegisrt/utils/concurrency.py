
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Coroutine, TypeVar

T = TypeVar("T")
R = TypeVar("R")

def run_concurrent(
    fn: Callable[[T], R],
    items: list[T],
    max_workers: int = 4,
) -> list[R]:
    if not items:
        return []

    results: list[R | None] = [None] * len(items)
    errors: list[Exception] = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_idx = {
            pool.submit(fn, item): idx for idx, item in enumerate(items)
        }
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception as exc:
                errors.append(exc)

    if errors:
        raise errors[0]

    return results
async def run_async_concurrent(
    fn: Callable[[T], Coroutine[Any, Any, R]],
    items: list[T],
    max_workers: int = 4,
) -> list[R]:
    if not items:
        return []

    sem = asyncio.Semaphore(max_workers)

    async def _wrapped(item: T) -> R:
        async with sem:
            return await fn(item)

    tasks = [asyncio.ensure_future(_wrapped(item)) for item in items]
    return list(await asyncio.gather(*tasks))
