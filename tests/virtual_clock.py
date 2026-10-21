"""A virtual clock, so timing behaviour can be tested without waiting.

A rate limiter is the component whose interesting behaviour all lives at the
boundary of a time window, and testing one against the real clock gives a
choice between a suite that takes minutes and assertions weaker than the limit
being checked. Neither is acceptable for the piece of this library that decides
whether an account gets banned.

The first attempt at this was four lines: a counter that sleep advanced by the
duration it was given. It produced waits of 15, 15, 15, 15 where the bucket was
handing out 15, 30, 45, 60, and the bucket was right. A real event loop runs
concurrent sleeps concurrently, so a shared counter that moves forward on every
call makes each waiter observe the time its predecessors spent sleeping, and
the limiter appears to refill while they wait.

So this behaves like an event loop's timer instead. A sleep registers a
deadline and parks. Time only moves when nothing is runnable, and then it moves
to the earliest deadline, waking everything due at that instant. Concurrent
sleeps therefore overlap, which is the property the four line version lacked.
"""

from __future__ import annotations

import asyncio
import heapq
import itertools


class VirtualClock:
    """A monotonic clock whose hands move only when every task is parked."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start
        self._pending: list[tuple[float, int, asyncio.Future[None]]] = []
        self._order = itertools.count()
        self.sleeps = 0

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps += 1
        if seconds <= 0:
            # Still yields, so a zero sleep behaves like asyncio.sleep(0) and
            # gives other tasks a chance to run.
            await asyncio.sleep(0)
            return
        waiter: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        heapq.heappush(self._pending, (self.now + seconds, next(self._order), waiter))
        await waiter

    def _advance_once(self) -> bool:
        while self._pending and self._pending[0][2].cancelled():
            heapq.heappop(self._pending)
        if not self._pending:
            return False
        deadline = self._pending[0][0]
        self.now = max(self.now, deadline)
        while self._pending and self._pending[0][0] <= self.now:
            _, _, waiter = heapq.heappop(self._pending)
            if not waiter.done():
                waiter.set_result(None)
        return True

    async def run(self, *awaitables, timeout_steps: int = 10_000):
        """Run ``awaitables`` to completion, advancing time when they park.

        Returns their results in order. ``timeout_steps`` bounds the number of
        times the clock may move, so a test that accidentally writes an endless
        wait fails rather than hanging a suite.
        """
        tasks = [asyncio.ensure_future(item) for item in awaitables]
        try:
            for _ in range(timeout_steps):
                # Let everything that can run, run, until all tasks are either
                # finished or parked on this clock.
                while True:
                    before = (len(self._pending), sum(task.done() for task in tasks))
                    await asyncio.sleep(0)
                    if (len(self._pending), sum(task.done() for task in tasks)) == before:
                        break
                if all(task.done() for task in tasks):
                    return [task.result() for task in tasks]
                if not self._advance_once():
                    # Nothing is pending on this clock and something is
                    # unfinished, so it is blocked on something else. Let the
                    # real loop settle it.
                    await asyncio.sleep(0)
                    if all(task.done() for task in tasks):
                        return [task.result() for task in tasks]
                    raise AssertionError("tasks are blocked on something other than this clock")
            raise AssertionError(f"clock advanced {timeout_steps} times without finishing")
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
