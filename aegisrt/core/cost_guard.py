
from __future__ import annotations

import logging
import threading

from aegisrt.core.metrics import estimate_cost

logger = logging.getLogger(__name__)


class BudgetExceededError(RuntimeError):

    def __init__(self, spent: float, limit: float) -> None:
        self.spent = spent
        self.limit = limit
        super().__init__(
            f"Budget exceeded: ${spent:.4f} spent of ${limit:.4f} limit"
        )


class CostGuard:

    def __init__(
        self,
        max_usd: float = 0.0,
        warn_at_pct: float = 0.8,
        model: str = "",
    ) -> None:
        self._max_usd = max_usd
        self._warn_at_pct = warn_at_pct
        self._default_model = model
        self._total_spent: float = 0.0
        self._total_calls: int = 0
        self._total_tokens_in: int = 0
        self._total_tokens_out: int = 0
        self._warned: bool = False
        self._lock = threading.Lock()


    def record(
        self,
        tokens_in: int,
        tokens_out: int,
        model: str = "",
    ) -> None:
        model_name = model or self._default_model
        cost = estimate_cost(model_name, tokens_in, tokens_out)

        with self._lock:
            self._total_spent += cost
            self._total_calls += 1
            self._total_tokens_in += tokens_in
            self._total_tokens_out += tokens_out

            if self._max_usd > 0:
                pct = self._total_spent / self._max_usd

                if pct >= self._warn_at_pct and not self._warned:
                    self._warned = True
                    logger.warning(
                        "CostGuard: %.0f%% of budget used "
                        "($%.4f / $%.4f)",
                        pct * 100,
                        self._total_spent,
                        self._max_usd,
                    )

                if self._total_spent >= self._max_usd:
                    raise BudgetExceededError(
                        self._total_spent, self._max_usd
                    )

    def check(self) -> None:
        with self._lock:
            if self._max_usd > 0 and self._total_spent >= self._max_usd:
                raise BudgetExceededError(
                    self._total_spent, self._max_usd
                )

    @property
    def enabled(self) -> bool:
        return self._max_usd > 0

    @property
    def total_spent(self) -> float:
        with self._lock:
            return self._total_spent

    @property
    def remaining(self) -> float:
        with self._lock:
            if self._max_usd <= 0:
                return float("inf")
            return max(0.0, self._max_usd - self._total_spent)

    @property
    def total_calls(self) -> int:
        with self._lock:
            return self._total_calls

    @property
    def total_tokens(self) -> tuple[int, int]:
        with self._lock:
            return self._total_tokens_in, self._total_tokens_out

    @property
    def utilization(self) -> float:
        with self._lock:
            if self._max_usd <= 0:
                return 0.0
            return min(self._total_spent / self._max_usd, 1.0)

    def summary(self) -> dict:
        with self._lock:
            if self._max_usd <= 0:
                util = 0.0
            else:
                util = min(self._total_spent / self._max_usd, 1.0)

            return {
                "max_usd": self._max_usd,
                "total_spent_usd": round(self._total_spent, 6),
                "remaining_usd": round(
                    max(0.0, self._max_usd - self._total_spent), 6
                )
                if self._max_usd > 0
                else None,
                "utilization_pct": round(util * 100, 2),
                "total_calls": self._total_calls,
                "total_tokens_in": self._total_tokens_in,
                "total_tokens_out": self._total_tokens_out,
            }
