import asyncio

import pytest

from iec.limits.bucket import Rate, TokenBucket
from tests.virtual_clock import VirtualClock


def bucket(allowance=4, per_seconds=60.0, burst=None):
    clock = VirtualClock()
    return clock, TokenBucket(Rate(allowance, per_seconds, burst), clock=clock, sleep=clock.sleep)


class TestRate:
    @pytest.mark.parametrize("kwargs", [{"allowance": 0}, {"allowance": -1}])
    def test_allowance_must_be_positive(self, kwargs):
        with pytest.raises(ValueError, match="allowance"):
            Rate(per_seconds=60.0, **kwargs)

    @pytest.mark.parametrize("per_seconds", [0, -5.0])
    def test_window_must_be_positive(self, per_seconds):
        with pytest.raises(ValueError, match="per_seconds"):
            Rate(4, per_seconds)

    def test_burst_must_be_at_least_one(self):
        with pytest.raises(ValueError, match="burst"):
            Rate(4, 60.0, burst=0)

    def test_burst_defaults_to_the_allowance(self):
        assert Rate(4, 60.0).capacity == 4
        assert Rate(4, 60.0, burst=1).capacity == 1

    def test_seconds_per_token_is_the_window_divided_by_the_allowance(self):
        assert Rate(4, 60.0).seconds_per_token == 15.0
        assert Rate(1000, 86400.0).seconds_per_token == pytest.approx(86.4)


class TestAcquire:
    async def test_the_burst_is_free_then_tokens_are_spaced(self):
        """Four per minute means four may go together and the fifth waits for
        the window to move, which is how a sliding window provider behaves."""
        clock, limiter = bucket()
        waits = await clock.run(*(limiter.acquire() for _ in range(10)))
        assert waits == [0.0, 0.0, 0.0, 0.0, 15.0, 30.0, 45.0, 60.0, 75.0, 90.0]

    async def test_concurrent_waiters_sleep_concurrently(self):
        """The reason the lock is not held across the sleep.

        Six callers against four per minute need the sixth to wait 30 seconds,
        for the two tokens ahead of it. An implementation that slept under the
        lock would make it wait for two sequential sleeps, so the total elapsed
        time would be the sum of every wait rather than the largest.
        """
        clock, limiter = bucket()
        waits = await clock.run(*(limiter.acquire() for _ in range(6)))
        assert max(waits) == 30.0
        assert clock.now == 30.0, "elapsed time should be the longest wait, not the sum"

    async def test_a_token_is_never_handed_to_two_callers(self):
        """The property the reservation exists for.

        Checking availability, releasing the lock and then decrementing leaves
        a window where every waiter sees the same free token. This asserts the
        grant count against what the rate allows over the elapsed window.
        """
        clock, limiter = bucket(allowance=5, per_seconds=10.0)
        await clock.run(*(limiter.acquire() for _ in range(25)))
        # 5 free at the start, then 5 every 10 seconds. The 25th token falls
        # due at 40 seconds.
        assert clock.now == 40.0
        assert limiter.granted == 25

    async def test_tokens_refill_while_nothing_is_asking(self):
        clock, limiter = bucket()
        await clock.run(*(limiter.acquire() for _ in range(4)))
        assert limiter.available == pytest.approx(0.0)
        clock.now += 30.0
        assert limiter.available == pytest.approx(2.0)

    async def test_refill_is_capped_at_the_burst(self):
        clock, limiter = bucket()
        clock.now += 86_400.0
        assert limiter.available == 4.0

    async def test_waited_seconds_accumulates_only_real_waits(self):
        clock, limiter = bucket()
        await clock.run(*(limiter.acquire() for _ in range(6)))
        assert limiter.waited_seconds == 15.0 + 30.0

    async def test_a_single_caller_in_a_loop_is_paced(self):
        clock, limiter = bucket(allowance=2, per_seconds=4.0)

        async def pump():
            for _ in range(6):
                await limiter.acquire()
            return clock.now

        [elapsed] = await clock.run(pump())
        # 2 free, then one every 2 seconds for the remaining 4.
        assert elapsed == 8.0


class TestTryAcquire:
    def test_it_takes_a_token_when_one_is_available(self):
        _, limiter = bucket()
        assert limiter.try_acquire() is True
        assert limiter.granted == 1

    def test_it_refuses_rather_than_waiting(self):
        """A hedge that waits for a token is not a hedge. It is a second
        request issued late, at the cost of the quota that would have served a
        different alert."""
        _, limiter = bucket(allowance=1, per_seconds=60.0)
        assert limiter.try_acquire() is True
        assert limiter.try_acquire() is False
        assert limiter.granted == 1

    def test_it_succeeds_again_once_a_token_has_refilled(self):
        clock, limiter = bucket(allowance=1, per_seconds=10.0)
        assert limiter.try_acquire() is True
        assert limiter.try_acquire() is False
        clock.now += 10.0
        assert limiter.try_acquire() is True

    def test_it_does_not_yield_so_no_other_task_can_interleave(self):
        """Synchronous on purpose: there is no await inside, so there is no
        point at which two coroutines can both see the same last token."""
        _, limiter = bucket(allowance=3, per_seconds=60.0)
        granted = [limiter.try_acquire() for _ in range(5)]
        assert granted == [True, True, True, False, False]


class TestVirtualClockItself:
    """The harness gets tests too, because its first version was wrong and
    blamed the bucket.

    A counter that sleep advanced by its own duration made each waiter observe
    the time its predecessors spent sleeping, so the bucket appeared to hand
    out 15, 15, 15, 15 where it was correctly handing out 15, 30, 45, 60.
    """

    async def test_concurrent_sleeps_overlap_rather_than_queueing(self):
        clock = VirtualClock()

        async def nap(seconds):
            await clock.sleep(seconds)
            return clock.now

        finished = await clock.run(nap(5), nap(5), nap(5))
        assert finished == [5.0, 5.0, 5.0]
        assert clock.now == 5.0

    async def test_sleeps_wake_in_deadline_order(self):
        clock = VirtualClock()
        woken: list[float] = []

        async def nap(seconds):
            await clock.sleep(seconds)
            woken.append(seconds)

        await clock.run(nap(30), nap(10), nap(20))
        assert woken == [10, 20, 30]

    async def test_a_zero_sleep_still_yields(self):
        clock = VirtualClock()
        order: list[str] = []

        async def first():
            order.append("a")
            await clock.sleep(0)
            order.append("c")

        async def second():
            order.append("b")

        await clock.run(first(), second())
        assert order == ["a", "b", "c"]

    async def test_a_task_blocked_on_something_else_is_reported(self):
        clock = VirtualClock()

        async def blocked():
            await asyncio.Event().wait()

        with pytest.raises(AssertionError, match="blocked on something other than this clock"):
            await clock.run(blocked())

    async def test_an_endless_wait_fails_rather_than_hanging(self):
        clock = VirtualClock()

        async def forever():
            while True:
                await clock.sleep(1)

        with pytest.raises(AssertionError, match="without finishing"):
            await clock.run(forever(), timeout_steps=50)
