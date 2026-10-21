"""Sends a second request when the first one is slow, if the budget allows.

Hedging is the standard answer to a long tail: issue a duplicate after a short
delay and take whichever answer arrives first. Against an unmetered service it
is close to free, because the only cost is some wasted server work.

Against a metered one it is not free, and this module was built on the belief
that it was expensive. The benchmark says that was overstated, and the number is
worth stating here rather than only in the ADR, because the docstring was wrong
first.

A hedge only fires on a request that has already stalled, so its cost is
bounded by the stall rate rather than by the traffic. On the simulated latency
model, where 2% of responses stall, hedging after 400ms cut the simulated p99
by 73% for 5.4% more requests. That is cheap insurance, not an expensive trade,
and the original framing had the magnitude wrong by an order of magnitude.

What survives the correction is the shape of the decision. The cost is small
but it is not zero, it lands on the same allowance that serves alerts with no
answer at all, and it scales with however badly the provider is behaving today
rather than with anything this library controls. A provider having a bad hour
is exactly when the stall rate climbs, which is exactly when hedging spends
most, which is exactly when the budget is least able to absorb it. So the
decision still cannot be a boolean set at startup, and the quota floor stays.

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
change reported with half its consequence left out, in whichever direction the
number happens to fall.

Hedging is off by default even so. 5% more requests is cheap, and it is still
5% a caller did not ask for, and the stall rate it depends on is a property of
somebody else's service rather than of this library. A default that quietly
spends more of a user's allowance than they expected is not made acceptable by
the spending being small.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Generic, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class Attempt(Generic[T]):
    """What one hedged call did.

    ``requests`` is this call's own count, returned rather than left to be
    inferred from the shared counters. Comparing ``stats.sent`` before and
    after looks equivalent and is not: with sixty four lookups in flight
    against one hedger, the difference picks up hedges other calls sent, and a
    benchmark run reported 583 provider requests for 217 lookups, which is more
    than one hedge each and therefore impossible. The same mistake, a counter
    delta standing in for a per call fact, had already been made once in the
    coalescer.
    """

    value: T
    requests: int
    won_by_hedge: bool


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

    async def run(self, factory: Callable[[], Awaitable[T]]) -> Attempt[T]:
        """Run ``factory``, hedging if the policy and the budget allow."""
        first = asyncio.ensure_future(factory())
        if not self._policy.enabled:
            return Attempt(await first, 1, False)

        done, _ = await asyncio.wait({first}, timeout=self._policy.after_seconds)
        if done:
            return Attempt(first.result(), 1, False)

        self.stats.eligible += 1
        if not self._may_hedge():
            return Attempt(await first, 1, False)

        self.stats.sent += 1
        second = asyncio.ensure_future(factory())
        try:
            done, pending = await asyncio.wait({first, second}, return_when=asyncio.FIRST_COMPLETED)
            # Whichever finished, the other is no longer needed. Cancelling it
            # does not refund the token: it was spent when the request went
            # out, and pretending otherwise is how local accounting drifts from
            # what the provider has counted, so both count as requests.
            winner = next(iter(done))
            for task in pending:
                task.cancel()
            if winner is second:
                self.stats.won_by_hedge += 1
            return Attempt(winner.result(), 2, winner is second)
        finally:
            for task in (first, second):
                if not task.done():
                    task.cancel()
