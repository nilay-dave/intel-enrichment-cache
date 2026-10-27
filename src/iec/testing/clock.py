"""A virtual clock, so timing behaviour can be measured without waiting.

Used by the test suite and by the benchmark. Shipped in the package rather than
kept beside the tests because the benchmark needed it and, not having it,
wrote its own: the same four line counter described below, with the same
consequence. It reported hedging as having no measurable effect, because
concurrent requests were being serialised by the clock rather than overlapping,
so nothing was ever still outstanding when the hedge delay elapsed.

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
from collections.abc import Callable


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

    async def run(
        self,
        *awaitables,
        timeout_steps: int = 10_000,
        real_wait_attempts: int = 200,
        activity: Callable[[], int] | None = None,
    ):
        """Run ``awaitables`` to completion, advancing time when they park.

        Returns their results in order. ``timeout_steps`` bounds the number of
        times the clock may move, so a test that writes an endless wait fails
        rather than hanging a suite.

        ``real_wait_attempts`` is what lets this drive code that also does real
        work. A coroutine inside asyncio.to_thread, which is how this package
        reaches SQLite, is parked on a future another thread will resolve, not
        on virtual time, so the clock has nothing to advance and no way to tell
        that from a deadlock. An earlier version raised immediately in that
        situation, which made it unusable for anything touching the cache: the
        benchmark failed on its first replay with "blocked on something other
        than this clock" when the only thing happening was a disk read.

        So a real wait is given a bounded number of short real sleeps to
        resolve. A thread hop resolves in a few of them; something genuinely
        stuck exhausts them and is still reported.

        ``activity`` is how a caller whose real work happens in tasks this
        clock does not own reports that it is progressing. Without it the
        progress check sees only the awaitables passed in and the pending
        timers, so a driver coroutine that spawns its own tasks looks stuck
        whenever those tasks are completing without sleeping. That is exactly
        what a run of cache hits looks like, and it is how a benchmark replay
        came to fail with a deadlock report while it was in fact serving
        several thousand lookups a second from disk. Return any number that
        only ever goes up.
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
                if self._advance_once():
                    continue

                # Nothing is pending on this clock. Either real work is in
                # flight, or everything is stuck. Told apart by progress rather
                # than by a fixed number of attempts: a deep queue of thread
                # hops can take far longer than any attempt count guessed up
                # front, and a fixed budget made this fail on a replay whose
                # only problem was a few thousand queued disk reads. So the
                # budget resets whenever anything changes, and is only spent by
                # consecutive attempts in which nothing did.
                idle = 0
                progress = activity or (lambda: 0)
                marker = (sum(task.done() for task in tasks), len(self._pending), progress())
                while idle < real_wait_attempts:
                    await asyncio.sleep(0.001 if idle else 0)
                    if all(task.done() for task in tasks):
                        return [task.result() for task in tasks]
                    if self._pending:
                        break
                    current = (sum(task.done() for task in tasks), len(self._pending), progress())
                    idle = 0 if current != marker else idle + 1
                    marker = current
                else:
                    raise AssertionError("tasks are blocked on something other than this clock and did not resolve")
            raise AssertionError(f"clock advanced {timeout_steps} times without finishing")
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
