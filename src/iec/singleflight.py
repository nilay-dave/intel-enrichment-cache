"""Collapses concurrent lookups of the same indicator into one request.

A batch of alerts arriving together usually shares indicators: the same
command and control address across twenty alerts, the same dropper hash across
a hundred. Without coalescing that is twenty or a hundred requests for one
answer, and on a 500 a day allowance the first burst of the shift spends the
budget for the whole of it.

This is a separate saving from the cache and is counted separately. A cache hit
means somebody already asked and the answer was stored; a coalesced call means
somebody is asking right now and has not come back yet. Counting the second as
a cache hit would overstate what the cache achieves, and on a bursty stream the
two are not close to the same size.

The work runs as a task rather than inline in the first caller. The difference
only shows when that caller is cancelled, which in a SOAR worker means its
alert timed out, and inline work would take every other waiter's answer down
with it. As a task, the request completes and the remaining waiters are served.
A waiter that is itself cancelled shields the shared task, so one impatient
caller cannot cancel the request the others are waiting on.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TypeVar

T = TypeVar("T")


@dataclass
class FlightStats:
    started: int = 0
    coalesced: int = 0

    @property
    def requests_avoided(self) -> int:
        return self.coalesced

    @property
    def coalesce_rate(self) -> float:
        total = self.started + self.coalesced
        return self.coalesced / total if total else 0.0


class SingleFlight:
    """One in flight call per key, with the rest waiting on it."""

    def __init__(self) -> None:
        self._inflight: dict[str, asyncio.Task] = {}
        self.stats = FlightStats()

    @property
    def in_flight(self) -> int:
        return len(self._inflight)

    async def run(self, key: str, factory: Callable[[], Awaitable[T]]) -> T:
        """Run ``factory`` for ``key``, or await the call already running."""
        result, _ = await self.run_tracked(key, factory)
        return result

    async def run_tracked(self, key: str, factory: Callable[[], Awaitable[T]]) -> tuple[T, bool]:
        """As ``run``, and says whether this call coalesced onto another.

        The flag is returned rather than left for the caller to work out from
        the counters. Comparing the shared coalesced count before and after
        looks equivalent and is not: by the time the first caller's own await
        returns, every waiter behind it has already incremented that counter,
        so the leader reads its own request as coalesced. On a burst of 25 that
        reported 25 coalesced calls out of 25, which is one more than exists
        and makes the headline saving look better than it is.
        """
        existing = self._inflight.get(key)
        if existing is not None:
            self.stats.coalesced += 1
            # Shielded, so a waiter that gives up does not cancel the request
            # the other waiters are still relying on.
            return await asyncio.shield(existing), True

        task = asyncio.ensure_future(factory())
        self._inflight[key] = task
        self.stats.started += 1

        # Removal happens in a callback rather than in a finally, because the
        # first caller may be cancelled while the task runs on. A finally in
        # this coroutine would then drop the key while the task is still live,
        # and the next caller would start a second request for the same thing.
        task.add_done_callback(lambda finished, key=key: self._retire(key, finished))

        return await asyncio.shield(task), False

    def _retire(self, key: str, task: asyncio.Task) -> None:
        if self._inflight.get(key) is task:
            del self._inflight[key]
        if not task.cancelled():
            # Read the exception even when nothing is waiting, or asyncio logs
            # "exception was never retrieved" for a failure every caller
            # already saw and handled.
            task.exception()
