"""Sends a second request when the first one is slow, if the budget allows.

Hedging is the standard answer to a long tail: issue a duplicate after a short
delay and take whichever answer arrives first. Against an unmetered service it
is close to free, because the only cost is some wasted server work.

Against a metered one it is not free at all, and this is the thing most
implementations leave out. A hedge is a request. On a 500 a day allowance every
hedge is an enrichment that will not happen later in the shift, so hedging
trades a better p99 for a smaller number of alerts enriched. Whether that trade
is worth taking depends on how much budget is left, which means the decision
cannot be a boolean set at startup.

So a hedge has to clear three gates, and all three can refuse it:

1. The first request is still outstanding after the delay. Otherwise there is
   nothing to hedge.
2. A short window token is free right now, taken without waiting. A hedge that
   queues for a token is not a hedge; it is a second request issued late, at
   the cost of the quota that would have served a different alert.
3. Enough of the daily allowance is left. Below the floor the hedge is
   refused, because the last of the budget should go to alerts that have no
   answer at all rather than to a faster answer for one that is already on its
   way.

The benchmark reports latency and quota together for exactly this reason. A
hedging change that improves p99 and is reported without its quota cost is a
change reported with its most important consequence left out.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class HedgePolicy:
    """When a second request is worth sending."""

    enabled: bool = False
    # Set from the provider's observed p50 rather than guessed. Hedging at the
    # median doubles the request count; hedging well out in the tail costs
    # little and still catches the stalls that matter.
    after_seconds: float = 1.5
    # Fraction of the daily allowance that must remain. Below it, no hedging:
    # the last of the budget belongs to alerts with no answer at all.
    min_remaining_fraction: float = 0.25
    # Never hedge more than once. A second hedge is a third request for one
    # answer, and if two have both stalled the provider is the problem.
    max_attempts: int = 2

    def __post_init__(self) -> None:
        if self.after_seconds <= 0:
            raise ValueError("after_seconds must be positive")
        if not 0.0 <= self.min_remaining_fraction <= 1.0:
            raise ValueError("min_remaining_fraction must be between 0 and 1")
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")


@dataclass
class HedgeStats:
    """What hedging actually did, so its cost can be weighed against its gain."""

    eligible: int = 0
    sent: int = 0
    refused_no_token: int = 0
    refused_low_quota: int = 0
    won_by_hedge: int = 0

    @property
    def extra_requests(self) -> int:
        """Requests hedging spent that a non hedged client would not have."""
        return self.sent


class Hedger:
    """Runs a request with an optional duplicate behind it."""

    def __init__(
        self,
        policy: HedgePolicy,
        *,
        has_token: Callable[[], bool],
        remaining_fraction: Callable[[], float],
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._policy = policy
        self._has_token = has_token
        self._remaining_fraction = remaining_fraction
        self._sleep = sleep
        self.stats = HedgeStats()

    def _may_hedge(self) -> bool:
        if self._remaining_fraction() < self._policy.min_remaining_fraction:
            self.stats.refused_low_quota += 1
            return False
        if not self._has_token():
            self.stats.refused_no_token += 1
            return False
        return True

    async def run(self, factory: Callable[[], Awaitable[T]]) -> tuple[T, bool]:
        """Run ``factory``, hedging if the policy and the budget allow.

        Returns the result and whether the hedge is the one that produced it.
        """
        first = asyncio.ensure_future(factory())
        if not self._policy.enabled:
            return await first, False

        done, _ = await asyncio.wait({first}, timeout=self._policy.after_seconds)
        if done:
            return first.result(), False

        self.stats.eligible += 1
        if not self._may_hedge():
            return await first, False

        self.stats.sent += 1
        second = asyncio.ensure_future(factory())
        try:
            done, pending = await asyncio.wait({first, second}, return_when=asyncio.FIRST_COMPLETED)
            # Whichever finished, the other is no longer needed. Cancelling it
            # does not refund the token: it was spent when the request went
            # out, and pretending otherwise is how local accounting drifts from
            # what the provider has counted.
            winner = next(iter(done))
            for task in pending:
                task.cancel()
            if winner is second:
                self.stats.won_by_hedge += 1
            return winner.result(), winner is second
        finally:
            for task in (first, second):
                if not task.done():
                    task.cancel()
