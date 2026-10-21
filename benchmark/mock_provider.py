"""A provider that answers from a latency model instead of a network.

**The latencies this produces are simulated.** There is no real API behind
them, and every latency figure derived from this file is labelled a simulation
wherever it is published. The quota figures are not simulated: a hit rate and a
request count are properties of the caching algorithm on a given stream, and
they come out the same whatever the latency model says.

The shape is lognormal with a separate stall tail, which is the shape HTTP
latency against a third party actually has: a tight body around the median and
a small fraction of responses an order of magnitude slower, from a cold cache
at the far end, a retried TLS handshake or a loaded shard. The stall tail is
the whole reason hedging exists, so a model without one would make hedging look
pointless and a model that was all tail would make it look free.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import numpy as np

from iec.models import Disposition, Indicator, IndicatorClass, ProviderVerdict


@dataclass(frozen=True)
class LatencyModel:
    """A simulated response time distribution.

    median_ms and sigma describe the lognormal body. stall_rate of responses
    instead take stall_multiplier times the median, which is the tail hedging
    is meant to cut.
    """

    median_ms: float = 180.0
    sigma: float = 0.45
    stall_rate: float = 0.02
    stall_multiplier: float = 12.0

    def sample(self, rng: np.random.Generator, size: int) -> np.ndarray:
        body = rng.lognormal(mean=np.log(self.median_ms), sigma=self.sigma, size=size)
        stalled = rng.random(size) < self.stall_rate
        return np.where(stalled, body * self.stall_multiplier, body)


class MockProvider:
    """Answers every lookup after a drawn delay.

    Each call draws its own delay, which is what makes hedging able to win: a
    second request for the same indicator is an independent draw, so a hedge
    behind a stalled first request usually lands in the body of the
    distribution. A model that returned the same latency per indicator would
    make hedging useless by construction and would be the wrong model, since
    nothing about an indicator makes the provider slow.
    """

    name = "mock"
    supports = frozenset(IndicatorClass)

    def __init__(
        self,
        model: LatencyModel,
        *,
        sleep: Callable[[float], Awaitable[None]],
        seed: int = 11,
        malicious_share: float = 0.08,
        unknown_share: float = 0.35,
    ) -> None:
        self._model = model
        self._sleep = sleep
        self._rng = np.random.default_rng(seed)
        self._malicious_share = malicious_share
        self._unknown_share = unknown_share
        self.calls = 0
        self.latencies_ms: list[float] = []

    async def lookup(self, indicator: Indicator) -> ProviderVerdict:
        self.calls += 1
        delay_ms = float(self._model.sample(self._rng, 1)[0])
        self.latencies_ms.append(delay_ms)
        await self._sleep(delay_ms / 1000.0)

        # A verdict drawn from the indicator's own text rather than at random,
        # so replaying the same stream twice gives the same dispositions and
        # the cache lifetimes exercised are the same each run.
        draw = (hash(indicator.key) % 10_000) / 10_000
        if draw < self._malicious_share:
            return ProviderVerdict(self.name, Disposition.MALICIOUS, 0.9, {"simulated": True})
        if draw < self._malicious_share + self._unknown_share:
            return ProviderVerdict(self.name, Disposition.UNKNOWN, None, {"simulated": True})
        return ProviderVerdict(self.name, Disposition.HARMLESS, 0.0, {"simulated": True})
