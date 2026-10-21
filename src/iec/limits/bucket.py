"""A token bucket that is correct when several coroutines want a token at once.

The obvious implementation holds the lock while it sleeps:

    async with self._lock:
        while not self._tokens:
            await asyncio.sleep(self._interval)
        self._tokens -= 1

That is correct and useless. Twenty coroutines waiting on a four per minute
limit queue behind each other's sleeps, so the twentieth waits for nineteen
sequential sleeps instead of for the nineteen tokens it actually needs. The
limiter becomes the thing that serialises the client it was meant to pace.

So waiters reserve rather than wait. The lock is held only long enough to work
out when this caller's token is due, which is a few microseconds of
arithmetic. The sleep happens outside, so twenty callers sleep concurrently and
wake in the order their slots come up. The lock never covers an await on
anything but itself.

The reservation is also what makes the limit hold under concurrency. A bucket
that checks availability, releases the lock and then decrements has a window
where every waiter sees the same free token. Here the slot is taken at the
moment it is calculated, so two callers cannot be given one token.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class Rate:
    """``allowance`` requests every ``per_seconds``, burstable to ``burst``.

    ``burst`` defaults to the allowance, which is what a sliding window
    provider behaves like: four requests may go out together, and the fifth
    waits for the window to move rather than for an evenly spaced slot.
    """

    allowance: int
    per_seconds: float
    burst: int | None = None

    def __post_init__(self) -> None:
        if self.allowance <= 0:
            raise ValueError("allowance must be positive")
        if self.per_seconds <= 0:
            raise ValueError("per_seconds must be positive")
        if self.burst is not None and self.burst < 1:
            raise ValueError("burst must be at least 1")

    @property
    def capacity(self) -> int:
        return self.burst if self.burst is not None else self.allowance

    @property
    def seconds_per_token(self) -> float:
        return self.per_seconds / self.allowance


class TokenBucket:
    """Paces requests to a ``Rate``.

    The clock and the sleep are injected. A rate limiter tested against the
    real clock is a test suite that either takes minutes or asserts something
    weaker than the limit it is checking, and a limiter is exactly the kind of
    component whose edge cases only appear at the boundary of a window.
    """

    def __init__(
        self,
        rate: Rate,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        self._rate = rate
        self._clock = clock
        self._sleep = sleep or asyncio.sleep
        self._lock = asyncio.Lock()
        self._tokens = float(rate.capacity)
        self._updated = clock()
        self.granted = 0
        self.waited_seconds = 0.0

    @property
    def rate(self) -> Rate:
        return self._rate

    def _refill(self, now: float) -> None:
        elapsed = now - self._updated
        if elapsed <= 0:
            return
        self._tokens = min(self._rate.capacity, self._tokens + elapsed / self._rate.seconds_per_token)
        self._updated = now

    async def acquire(self) -> float:
        """Take one token, waiting if none is due yet. Returns seconds waited."""
        async with self._lock:
            now = self._clock()
            self._refill(now)
            if self._tokens >= 1:
                self._tokens -= 1
                self.granted += 1
                return 0.0
            # Not available. Take the slot now and work out when it falls due,
            # so the next caller reserves the one after it rather than racing
            # for the same one.
            shortfall = 1 - self._tokens
            wait = shortfall * self._rate.seconds_per_token
            self._tokens -= 1
            self.granted += 1

        self.waited_seconds += wait
        await self._sleep(wait)
        return wait

    def try_acquire(self) -> bool:
        """Take a token only if one is available now.

        Synchronous and lock free: it touches the token count without awaiting,
        so there is no point at which another coroutine can run in between.
        This is what hedging uses, because a hedge that waits for a token is
        not a hedge, it is a second request issued late at the cost of the
        quota that would have served a different alert.
        """
        now = self._clock()
        self._refill(now)
        if self._tokens >= 1:
            self._tokens -= 1
            self.granted += 1
            return True
        return False

    @property
    def available(self) -> float:
        """Tokens available now, without taking one."""
        self._refill(self._clock())
        return self._tokens
