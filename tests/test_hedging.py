import asyncio

import pytest

from iec.hedging import HedgePolicy, Hedger


class Attempts:
    """A factory whose nth call takes delays[n] seconds."""

    def __init__(self, *delays: float) -> None:
        self.delays = delays
        self.calls = 0

    async def __call__(self) -> str:
        index = self.calls
        self.calls += 1
        await asyncio.sleep(self.delays[min(index, len(self.delays) - 1)])
        return f"attempt-{index}"


def hedger(policy: HedgePolicy, *, token=True, remaining=1.0) -> Hedger:
    return Hedger(policy, has_token=lambda: token, remaining_fraction=lambda: remaining)


class TestPolicyValidation:
    def test_the_delay_must_be_positive(self):
        with pytest.raises(ValueError, match="after_seconds"):
            HedgePolicy(after_seconds=0)

    @pytest.mark.parametrize("fraction", [-0.1, 1.1])
    def test_the_quota_floor_must_be_a_fraction(self, fraction):
        with pytest.raises(ValueError, match="min_remaining_fraction"):
            HedgePolicy(min_remaining_fraction=fraction)

    def test_attempts_must_be_at_least_one(self):
        with pytest.raises(ValueError, match="max_attempts"):
            HedgePolicy(max_attempts=0)

    def test_hedging_is_off_by_default(self):
        """It spends quota, so it is opt in. A library that hedged by default
        would quietly halve the number of alerts a free tier can enrich."""
        assert HedgePolicy().enabled is False


class TestDisabled:
    async def test_no_second_request_is_ever_sent(self):
        work = Attempts(0.05)
        attempt = await hedger(HedgePolicy(enabled=False)).run(work)
        assert attempt.value == "attempt-0"
        assert attempt.won_by_hedge is False
        assert work.calls == 1

    async def test_nothing_is_counted_as_eligible(self):
        agent = hedger(HedgePolicy(enabled=False))
        await agent.run(Attempts(0.05))
        assert agent.stats.eligible == 0
        assert agent.stats.sent == 0


class TestEnabled:
    async def test_a_fast_first_response_is_not_hedged(self):
        work = Attempts(0.001)
        agent = hedger(HedgePolicy(enabled=True, after_seconds=0.05))
        attempt = await agent.run(work)
        assert attempt.value == "attempt-0"
        assert attempt.won_by_hedge is False
        assert work.calls == 1
        assert agent.stats.eligible == 0

    async def test_a_slow_first_response_is_hedged(self):
        work = Attempts(0.2, 0.01)
        agent = hedger(HedgePolicy(enabled=True, after_seconds=0.02))
        attempt = await agent.run(work)
        assert attempt.value == "attempt-1"
        assert attempt.won_by_hedge is True
        assert work.calls == 2
        assert agent.stats.sent == 1
        assert agent.stats.won_by_hedge == 1

    async def test_the_first_request_can_still_win_the_race(self):
        """Then the hedge was spent for nothing, which is the cost that has to
        appear next to the latency improvement."""
        work = Attempts(0.04, 0.5)
        agent = hedger(HedgePolicy(enabled=True, after_seconds=0.01))
        attempt = await agent.run(work)
        assert attempt.value == "attempt-0"
        assert attempt.won_by_hedge is False
        assert agent.stats.sent == 1
        assert agent.stats.won_by_hedge == 0
        assert agent.stats.extra_requests == 1

    async def test_only_one_hedge_is_sent(self):
        """A second hedge is a third request for one answer, and if two have
        both stalled the provider is the problem."""
        work = Attempts(0.3, 0.3, 0.01)
        agent = hedger(HedgePolicy(enabled=True, after_seconds=0.01))
        await agent.run(work)
        assert work.calls == 2


class TestRefusals:
    async def test_a_hedge_is_refused_when_the_daily_budget_is_low(self):
        """The last of the budget belongs to alerts with no answer at all, not
        to a faster answer for one already on its way."""
        work = Attempts(0.05)
        agent = hedger(
            HedgePolicy(enabled=True, after_seconds=0.01, min_remaining_fraction=0.25), remaining=0.05
        )
        attempt = await agent.run(work)
        assert attempt.value == "attempt-0"
        assert attempt.won_by_hedge is False
        assert work.calls == 1
        assert agent.stats.eligible == 1
        assert agent.stats.refused_low_quota == 1

    async def test_a_hedge_is_refused_when_no_token_is_free(self):
        """A hedge that waits for a token is not a hedge. It is a second
        request issued late, at the cost of the quota that would have served a
        different alert."""
        work = Attempts(0.05)
        agent = hedger(HedgePolicy(enabled=True, after_seconds=0.01), token=False)
        attempt = await agent.run(work)
        assert attempt.won_by_hedge is False
        assert work.calls == 1
        assert agent.stats.refused_no_token == 1

    async def test_the_quota_floor_is_checked_before_the_token(self):
        """Taking a token and then refusing on quota would spend a token on a
        request never sent, and the bucket has no refund."""
        work = Attempts(0.05)
        taken = []
        agent = Hedger(
            HedgePolicy(enabled=True, after_seconds=0.01, min_remaining_fraction=0.5),
            has_token=lambda: (taken.append(1), True)[1],
            remaining_fraction=lambda: 0.1,
        )
        await agent.run(work)
        assert taken == []
        assert agent.stats.refused_low_quota == 1


class TestFailures:
    async def test_an_error_from_the_only_request_propagates(self):
        async def boom():
            raise RuntimeError("provider down")

        with pytest.raises(RuntimeError, match="provider down"):
            await hedger(HedgePolicy(enabled=False)).run(boom)

    async def test_the_hedge_answers_when_the_first_request_fails_slowly(self):
        calls = []

        async def first_fails():
            index = len(calls)
            calls.append(1)
            if index == 0:
                await asyncio.sleep(0.05)
                raise RuntimeError("timeout")
            await asyncio.sleep(0.01)
            return "hedge won"

        attempt = await hedger(HedgePolicy(enabled=True, after_seconds=0.01)).run(first_fails)
        assert attempt.value == "hedge won"
        assert attempt.won_by_hedge is True

    async def test_the_loser_is_cancelled_rather_than_left_running(self):
        running = []

        async def tracked():
            index = len(running)
            running.append("started")
            try:
                await asyncio.sleep(0.3 if index == 0 else 0.01)
                return f"attempt-{index}"
            except asyncio.CancelledError:
                running.append("cancelled")
                raise

        agent = hedger(HedgePolicy(enabled=True, after_seconds=0.01))
        await agent.run(tracked)
        await asyncio.sleep(0.02)
        assert "cancelled" in running


class TestRequestAccounting:
    """The count a caller charges its quota against.

    Returned per call rather than inferred from the shared counters. With sixty
    four lookups in flight against one hedger, a difference of stats.sent picks
    up hedges other calls sent: a benchmark run reported 583 provider requests
    for 217 lookups, which is more than one hedge each and so impossible.
    """

    async def test_an_unhedged_call_reports_one_request(self):
        attempt = await hedger(HedgePolicy(enabled=False)).run(Attempts(0.001))
        assert attempt.requests == 1

    async def test_a_hedged_call_reports_two(self):
        attempt = await hedger(HedgePolicy(enabled=True, after_seconds=0.01)).run(Attempts(0.2, 0.01))
        assert attempt.requests == 2

    async def test_a_refused_hedge_reports_one(self):
        attempt = await hedger(HedgePolicy(enabled=True, after_seconds=0.01), token=False).run(Attempts(0.05))
        assert attempt.requests == 1

    async def test_concurrent_calls_do_not_borrow_each_others_counts(self):
        """One hedger, many lookups. Each call's count is its own.

        The fast path returns without ever parking on a timer, so it is done
        before the first wait on it is evaluated and cannot hedge whatever the
        machine is doing. An earlier version slept for a millisecond against a
        twenty millisecond delay, which passed alone and failed inside the full
        suite, where the margin disappears under load. A test of accounting
        should not be a test of the scheduler.
        """
        agent = hedger(HedgePolicy(enabled=True, after_seconds=0.02))
        blocker = asyncio.Event()

        async def immediate():
            return "fast"

        async def blocked():
            await blocker.wait()
            return "slow"

        slow_call = asyncio.ensure_future(agent.run(blocked))
        quick = await asyncio.gather(*(agent.run(immediate) for _ in range(20)))
        blocker.set()
        slow = await slow_call

        assert slow.requests == 2, "the blocked call hedged, so it spent two"
        assert all(attempt.requests == 1 for attempt in quick)
        assert sum(attempt.requests for attempt in [*quick, slow]) == 22
