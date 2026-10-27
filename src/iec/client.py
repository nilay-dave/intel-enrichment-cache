"""The client: cache, then coalesce, then pace, then ask.

The order is the design. Each stage is cheaper than the one behind it and
exists to stop work reaching it.

1. **Cache.** Costs a local read. Answers most of a repeat heavy stream.
2. **Coalescing.** Costs a dictionary lookup. Answers the duplicates a cache
   cannot, because they are in flight rather than stored.
3. **Quota.** Costs a SQLite write. Refuses before anything leaves the
   process, so an exhausted allowance is never learned from the provider.
4. **Token bucket.** Costs a wait. Paces what does leave.
5. **Provider.** Costs a request and whatever the network charges in latency.

Three behaviours in here are worth stating because the obvious alternative is
worse.

**A partial answer beats an error.** Two providers, one times out, the other
answers: the answer is returned with the failure recorded alongside it. An
analyst with one verdict and a note about the other source is better served
than one with an exception, and a client that discards good data because some
other request failed is throwing away quota it has already spent.

**The worst verdict wins.** Merging by severity rather than by consensus or by
a mean. One provider calling an address malicious while another has never heard
of it is not a tie, and averaging a verdict with an absence of one produces a
number that means nothing.

**A provider refusing on its own accounting is a distinct outcome.** Reaching a
429 means the local limiter was wrong, which is a different problem from the
provider being down and calls for the opposite response: fix the preset rather
than retry. It is counted separately so the condition is visible rather than
buried among timeouts.
"""

from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from iec.cache.store import Cache, TTLPolicy
from iec.hedging import HedgePolicy, Hedger
from iec.limits.bucket import Rate, TokenBucket
from iec.limits.presets import Preset
from iec.limits.quota import DailyQuota, QuotaExhausted
from iec.models import Disposition, Enrichment, Indicator, ProviderVerdict, Source
from iec.providers.base import Provider, ProviderError, RateLimited
from iec.singleflight import SingleFlight

# Worst first. Merging picks the highest ranked disposition any provider
# returned, so an absence of data never dilutes a detection.
SEVERITY = {
    Disposition.MALICIOUS: 4,
    Disposition.SUSPICIOUS: 3,
    Disposition.HARMLESS: 2,
    Disposition.UNKNOWN: 1,
    Disposition.ERROR: 0,
}


@dataclass
class ClientStats:
    """What the benchmark reports. Counted, never derived from a sample."""

    requested: int = 0
    from_cache: int = 0
    coalesced: int = 0
    from_provider: int = 0
    quota_refused: int = 0
    provider_requests: int = 0
    provider_errors: int = 0
    provider_rate_limited: int = 0
    hedges_sent: int = 0
    hedges_won: int = 0
    latencies_ms: list[float] = field(default_factory=list)

    @property
    def cache_hit_rate(self) -> float:
        return self.from_cache / self.requested if self.requested else 0.0

    @property
    def avoided_rate(self) -> float:
        """Share of lookups that cost no request at all."""
        return (self.from_cache + self.coalesced) / self.requested if self.requested else 0.0

    def requests_per_thousand(self) -> float:
        return self.provider_requests / self.requested * 1000 if self.requested else 0.0

    def percentile(self, fraction: float) -> float:
        """The nearest rank percentile: the ceil(p * N)th smallest value.

        The definition is stated because the three common ones disagree by a
        whole index at small sample sizes, and a p99 gets read as though it
        were exact. This one never interpolates, so every number it reports is
        a latency that was actually observed rather than an average of two
        that were not.

        An earlier version indexed at round(p * (N - 1)), which is the base of
        the linear interpolation definition with the interpolation left out. It
        gave 51 as the median of 1 to 100.
        """
        if not self.latencies_ms:
            return 0.0
        ordered = sorted(self.latencies_ms)
        rank = max(1, math.ceil(fraction * len(ordered)))
        return ordered[min(rank, len(ordered)) - 1]


@dataclass(frozen=True)
class ProviderBudget:
    """A provider with the limits it is paced to."""

    provider: Provider
    rate: Rate
    daily_limit: int | None = None
    daily_window_seconds: float = 86_400.0

    @classmethod
    def from_preset(cls, provider: Provider, preset: Preset) -> ProviderBudget:
        return cls(
            provider=provider,
            rate=preset.rate,
            daily_limit=preset.daily_limit,
            daily_window_seconds=preset.daily_window_seconds,
        )


class EnrichmentClient:
    """Enriches indicators without spending more quota than it has to."""

    def __init__(
        self,
        budgets: Sequence[ProviderBudget],
        *,
        cache: Cache,
        quota: DailyQuota | Path | str,
        ttl: TTLPolicy | None = None,
        hedge: HedgePolicy | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], object] | None = None,
    ) -> None:
        if not budgets:
            raise ValueError("at least one provider budget is required")
        self._budgets = list(budgets)
        self._cache = cache
        self._quota = quota if isinstance(quota, DailyQuota) else DailyQuota(quota)
        self._ttl = ttl or TTLPolicy()
        self._hedge_policy = hedge or HedgePolicy()
        self._clock = clock
        self._flight = SingleFlight()
        self.stats = ClientStats()

        self._buckets = {
            budget.provider.name: TokenBucket(budget.rate, clock=clock, sleep=sleep or asyncio.sleep)
            for budget in self._budgets
        }
        self._hedgers = {
            budget.provider.name: Hedger(
                self._hedge_policy,
                has_token=self._buckets[budget.provider.name].try_acquire,
                remaining_fraction=lambda name=budget.provider.name: self._remaining_fraction(name),
                sleep=sleep or asyncio.sleep,
            )
            for budget in self._budgets
        }

    def _budget_for(self, name: str) -> ProviderBudget:
        return next(budget for budget in self._budgets if budget.provider.name == name)

    def _remaining_fraction(self, name: str) -> float:
        budget = self._budget_for(name)
        if budget.daily_limit is None:
            return 1.0
        remaining = self._quota.remaining(name, budget.daily_limit, budget.daily_window_seconds)
        return remaining / budget.daily_limit

    def remaining(self) -> dict[str, int | None]:
        """What is left today, per provider. For an operator, not the library."""
        return {
            budget.provider.name: (
                None
                if budget.daily_limit is None
                else self._quota.remaining(budget.provider.name, budget.daily_limit, budget.daily_window_seconds)
            )
            for budget in self._budgets
        }

    async def enrich(self, value: str | Indicator) -> Enrichment:
        """Enrich one indicator, spending as little quota as possible."""
        indicator = value if isinstance(value, Indicator) else Indicator.parse(value)
        self.stats.requested += 1
        started = self._clock()

        cached = await self._cache.get(indicator.key)
        if cached is not None:
            self.stats.from_cache += 1
            self.stats.latencies_ms.append((self._clock() - started) * 1000)
            return cached

        result, was_coalesced = await self._flight.run_tracked(indicator.key, lambda: self._fetch(indicator))
        if was_coalesced:
            self.stats.coalesced += 1
            # A coalesced answer was produced by somebody else's request, so
            # the source is rewritten. Reporting it as a provider answer would
            # double count the request that produced it.
            result = Enrichment(
                indicator=result.indicator,
                disposition=result.disposition,
                verdicts=result.verdicts,
                source=Source.COALESCED,
                fetched_at=result.fetched_at,
                hedged=result.hedged,
                error=result.error,
            )
        else:
            if result.source is Source.PROVIDER:
                self.stats.from_provider += 1
            elif result.source is Source.QUOTA_EXHAUSTED:
                self.stats.quota_refused += 1

        self.stats.latencies_ms.append((self._clock() - started) * 1000)
        return result

    async def enrich_many(self, values: Sequence[str | Indicator], *, concurrency: int = 8) -> list[Enrichment]:
        """Enrich a batch, which is the shape coalescing exists for.

        Bounded concurrency rather than unbounded: an unbounded gather over a
        thousand alerts opens a thousand coroutines that all queue on the same
        token bucket, which costs memory to achieve nothing, since the bucket
        is what decides the pace either way.
        """
        gate = asyncio.Semaphore(concurrency)

        async def one(value: str | Indicator) -> Enrichment:
            async with gate:
                return await self.enrich(value)

        return list(await asyncio.gather(*(one(value) for value in values)))

    async def _fetch(self, indicator: Indicator) -> Enrichment:
        verdicts: list[ProviderVerdict] = []
        errors: list[str] = []
        hedged_any = False
        asked = 0

        for budget in self._budgets:
            provider = budget.provider
            if indicator.kind not in provider.supports:
                continue
            asked += 1

            if budget.daily_limit is not None:
                try:
                    self._quota.charge(provider.name, budget.daily_limit, budget.daily_window_seconds)
                except QuotaExhausted as exc:
                    errors.append(str(exc))
                    continue

            await self._buckets[provider.name].acquire()
            hedger = self._hedgers[provider.name]

            try:
                attempt = await hedger.run(lambda provider=provider: provider.lookup(indicator))
            except RateLimited as exc:
                # The local limiter was wrong. Counted separately because the
                # fix is the preset, not a retry.
                self.stats.provider_rate_limited += 1
                self.stats.provider_requests += 1
                errors.append(str(exc))
                continue
            except ProviderError as exc:
                self.stats.provider_errors += 1
                self.stats.provider_requests += 1
                errors.append(str(exc))
                continue

            # Taken from the attempt rather than from a difference of the
            # shared counters, which under concurrency attributes other
            # lookups' hedges to this one.
            self.stats.provider_requests += attempt.requests
            self.stats.hedges_sent += attempt.requests - 1

            if attempt.won_by_hedge:
                hedged_any = True
                self.stats.hedges_won += 1
            verdicts.append(attempt.value)

        if not verdicts:
            quota_only = asked > 0 and self.stats.provider_errors == 0 and self.stats.provider_rate_limited == 0
            return Enrichment(
                indicator=indicator,
                disposition=Disposition.ERROR,
                source=Source.QUOTA_EXHAUSTED if quota_only and errors else Source.PROVIDER,
                error="; ".join(errors) if errors else f"no provider supports {indicator.kind.value}",
            )

        disposition = max((verdict.disposition for verdict in verdicts), key=lambda item: SEVERITY[item])
        enrichment = Enrichment(
            indicator=indicator,
            disposition=disposition,
            verdicts=tuple(verdicts),
            source=Source.PROVIDER,
            hedged=hedged_any,
            # A partial answer carries the note about what failed. An analyst
            # with one verdict and a note beats one with an exception.
            error="; ".join(errors) if errors else None,
        )
        await self._cache.put(enrichment, self._ttl.seconds_for(indicator.kind, disposition))
        return enrichment
