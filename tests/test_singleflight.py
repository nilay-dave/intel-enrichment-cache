import asyncio

import pytest

from iec.singleflight import SingleFlight


class Counter:
    """Records how many times the factory actually ran."""

    def __init__(self, delay: float = 0.01, result: str = "answer") -> None:
        self.delay = delay
        self.result = result
        self.calls = 0

    async def __call__(self) -> str:
        self.calls += 1
        await asyncio.sleep(self.delay)
        return self.result


async def test_concurrent_callers_for_one_key_make_one_request():
    flight = SingleFlight()
    work = Counter()
    results = await asyncio.gather(*(flight.run("k", work) for _ in range(20)))
    assert results == ["answer"] * 20
    assert work.calls == 1
    assert flight.stats.started == 1
    assert flight.stats.coalesced == 19


async def test_different_keys_do_not_coalesce():
    flight = SingleFlight()
    work = Counter()
    await asyncio.gather(*(flight.run(f"k{index}", work) for index in range(5)))
    assert work.calls == 5
    assert flight.stats.coalesced == 0


async def test_a_sequential_caller_after_completion_starts_a_new_request():
    """Coalescing is not caching. Once the flight lands, the next caller asks
    again, and it is the cache's job to stop that being a request."""
    flight = SingleFlight()
    work = Counter()
    await flight.run("k", work)
    await flight.run("k", work)
    assert work.calls == 2
    assert flight.stats.coalesced == 0


async def test_the_key_is_released_once_the_flight_lands():
    flight = SingleFlight()
    work = Counter()
    await asyncio.gather(*(flight.run("k", work) for _ in range(3)))
    assert flight.in_flight == 0


async def test_a_failure_reaches_every_waiter_without_a_retry_storm():
    """Five waiters, one attempt, five errors. A per waiter retry would turn
    one provider outage into five times the requests at the worst moment."""
    flight = SingleFlight()
    attempts = []

    async def boom():
        attempts.append(1)
        await asyncio.sleep(0.01)
        raise RuntimeError("provider down")

    results = await asyncio.gather(*(flight.run("k", boom) for _ in range(5)), return_exceptions=True)
    assert len(attempts) == 1
    assert all(isinstance(result, RuntimeError) for result in results)
    assert flight.in_flight == 0


async def test_a_failure_does_not_poison_the_next_caller():
    flight = SingleFlight()

    async def boom():
        raise RuntimeError("transient")

    with pytest.raises(RuntimeError):
        await flight.run("k", boom)
    work = Counter()
    assert await flight.run("k", work) == "answer"


async def test_cancelling_the_first_caller_does_not_strand_the_others():
    """In a SOAR worker a cancelled caller means its alert timed out. Running
    the work inline would take every other waiter's answer with it."""
    flight = SingleFlight()
    work = Counter(delay=0.05)

    leader = asyncio.ensure_future(flight.run("k", work))
    await asyncio.sleep(0.005)
    follower = asyncio.ensure_future(flight.run("k", work))
    await asyncio.sleep(0.005)
    leader.cancel()

    assert await follower == "answer"
    assert work.calls == 1
    with pytest.raises(asyncio.CancelledError):
        await leader


async def test_cancelling_a_waiter_does_not_cancel_the_shared_request():
    """One impatient caller must not take down the request the rest are
    waiting on, which is what the shield is for."""
    flight = SingleFlight()
    work = Counter(delay=0.05)

    leader = asyncio.ensure_future(flight.run("k", work))
    await asyncio.sleep(0.005)
    impatient = asyncio.ensure_future(flight.run("k", work))
    await asyncio.sleep(0.005)
    impatient.cancel()

    assert await leader == "answer"
    assert work.calls == 1


async def test_cancelling_every_caller_still_retires_the_key():
    """Otherwise the key is held by a flight nobody is waiting for and the
    next caller coalesces onto a dead request."""
    flight = SingleFlight()
    work = Counter(delay=0.02)

    callers = [asyncio.ensure_future(flight.run("k", work)) for _ in range(3)]
    await asyncio.sleep(0.005)
    for caller in callers:
        caller.cancel()
    await asyncio.gather(*callers, return_exceptions=True)
    await asyncio.sleep(0.03)
    assert flight.in_flight == 0


async def test_the_coalesce_rate_counts_against_total_calls():
    flight = SingleFlight()
    work = Counter()
    await asyncio.gather(*(flight.run("k", work) for _ in range(4)))
    assert flight.stats.coalesce_rate == 0.75
    assert flight.stats.requests_avoided == 3


def test_the_coalesce_rate_is_zero_before_anything_runs():
    assert SingleFlight().stats.coalesce_rate == 0.0


async def test_the_leader_is_told_it_did_not_coalesce():
    """Comparing the shared counter before and after looks equivalent and is
    not: by the time the leader's own await returns, every waiter behind it has
    incremented that counter, so the leader reads its own request as coalesced.
    On a burst of 25 that reported 25 coalesced calls out of 25."""
    flight = SingleFlight()
    work = Counter(delay=0.02)
    flags = await asyncio.gather(*(flight.run_tracked("k", work) for _ in range(25)))
    coalesced = [was_coalesced for _, was_coalesced in flags]
    assert coalesced.count(False) == 1
    assert coalesced.count(True) == 24
