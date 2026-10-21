"""Measures what the cache, the coalescer and the hedger actually buy.

Three experiments, each driven by the simplest mechanism that answers its own
question. An earlier version drove all three through one general purpose
virtual clock and spent longer debugging the harness than writing the
measurement. The lesson is in ADR-003: a benchmark whose scaffolding is harder
to trust than the code under test is not measuring anything.

**A. Quota efficiency.** Real measurements. A hit rate and a request count are
properties of the algorithm on a stated stream, and nothing about them depends
on how long a request takes, so this experiment removes latency entirely. The
stream is replayed in arrival time order, grouped into windows: everything that
arrives inside one window is submitted together, which is what gives the
coalescer something to collapse, and the cache's clock is moved to each window
so lifetimes expire as real days pass.

**B. Cache lifetime policy.** The same replay under per class lifetimes and
under a single global one. The comparison ADR-001 rests on. Also real.

**C. Hedging.** Latency percentiles and requests spent, with hedging on and
off. **These latencies are simulated** from the model in mock_provider.py,
which is also the only experiment that needs real time to pass, so it runs on a
smaller sample against real asyncio with the drawn delays actually slept. The
request counts here are real, which is the half of the trade that matters,
because hedging's cost is paid in requests and its benefit only in latency.

No experiment paces requests. Pacing changes when a request goes out, not how
many, and with a four per minute limiter in the way every latency measured
would be queue time and the result would describe the limiter.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from dataclasses import asdict
from itertools import groupby
from pathlib import Path
from shutil import rmtree

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "benchmark"))

from mock_provider import LatencyModel, MockProvider  # noqa: E402
from stream import StreamSpec, describe, describe_arrivals, generate_timed  # noqa: E402

from iec import (  # noqa: E402
    DailyQuota,
    EnrichmentClient,
    HedgePolicy,
    ProviderBudget,
    Rate,
    SqliteCache,
    TTLPolicy,
    preset,
)

# Wide enough that the limiter is never the thing being measured.
UNPACED = Rate(allowance=1_000_000, per_seconds=1.0)

def fresh(room: Path) -> Path:
    """An empty directory, every time.

    The benchmark reused its workspace, so a cache and a quota ledger left by a
    previous run were still there when the next one started. One run served
    every lookup from a cache it had not populated, reported zero provider
    requests, and the derived "lookups per day" came out as infinity, which is
    how the bug announced itself. A benchmark whose result depends on what the
    last one left behind is not a measurement.
    """
    if room.exists():
        rmtree(room)
    room.mkdir(parents=True)
    return room


# Alerts arriving inside one window are submitted together, so the coalescer
# sees them as concurrent. Two seconds matches the burst spread in the stream
# model, which is the timescale on which a cluster of alerts actually lands.
WINDOW_SECONDS = 2.0


class Instant:
    """A provider with no latency at all, for the experiments about quota.

    Removing latency rather than simulating it is the point: a request count
    does not depend on how long a request takes, and a benchmark that models
    something it does not need has given itself a second thing to be wrong
    about.
    """

    name = "instant"

    def __init__(self, shared: MockProvider) -> None:
        self.supports = shared.supports
        self._shared = shared
        self.calls = 0

    async def lookup(self, indicator):
        self.calls += 1
        return await _verdict_only(self._shared, indicator)


async def _verdict_only(shared: MockProvider, indicator):
    # The same deterministic verdict the latency model would have returned,
    # without its delay, so dispositions and therefore cache lifetimes match
    # across experiments.
    draw = (hash(indicator.key) % 10_000) / 10_000
    from iec.models import Disposition, ProviderVerdict

    if draw < 0.08:
        return ProviderVerdict(shared.name, Disposition.MALICIOUS, 0.9, {"simulated": True})
    if draw < 0.43:
        return ProviderVerdict(shared.name, Disposition.UNKNOWN, None, {"simulated": True})
    return ProviderVerdict(shared.name, Disposition.HARMLESS, 0.0, {"simulated": True})


def windows(timed: list[tuple[float, str]], width: float) -> list[tuple[float, list[str]]]:
    """Group arrivals into fixed windows, keeping order."""
    grouped = []
    for bucket, members in groupby(timed, key=lambda item: int(item[0] // width)):
        indicators = [indicator for _, indicator in members]
        grouped.append((bucket * width, indicators))
    return grouped


async def replay_quota(timed, *, workspace: Path, ttl: TTLPolicy | None = None) -> dict:
    """Experiment A and B. No latency, real arrival times, real counts."""
    virtual = {"now": 0.0}
    cache = SqliteCache(workspace / "cache.sqlite", clock=lambda: 1_700_000_000.0 + virtual["now"])
    quota = DailyQuota(workspace / "quota.sqlite", clock=lambda: 1_700_000_000.0 + virtual["now"])
    shared = MockProvider(LatencyModel(), sleep=asyncio.sleep)
    provider = Instant(shared)

    client = EnrichmentClient(
        [ProviderBudget(provider=provider, rate=UNPACED, daily_limit=None)],
        cache=cache,
        quota=quota,
        ttl=ttl,
        clock=lambda: virtual["now"],
    )

    started = time.perf_counter()
    for when, indicators in windows(timed, WINDOW_SECONDS):
        virtual["now"] = when
        await client.enrich_many(indicators, concurrency=len(indicators))
    wall = time.perf_counter() - started
    cache.close()

    stats = client.stats
    return {
        "lookups": stats.requested,
        "provider_requests": stats.provider_requests,
        "from_cache": stats.from_cache,
        "coalesced": stats.coalesced,
        "cache_hit_rate": round(stats.cache_hit_rate, 4),
        "avoided_rate": round(stats.avoided_rate, 4),
        "requests_per_1000_lookups": round(stats.requests_per_thousand(), 1),
        "simulated_days_elapsed": round(virtual["now"] / 86_400, 2),
        "wall_seconds": round(wall, 2),
        "lookups_per_wall_second": round(stats.requested / wall) if wall else 0,
    }


async def replay_latency(timed, *, workspace: Path, hedge: HedgePolicy, model: LatencyModel) -> dict:
    """Experiment C. Real asyncio, real sleeps, simulated delays."""
    cache = SqliteCache(workspace / "cache.sqlite")
    quota = DailyQuota(workspace / "quota.sqlite")
    provider = MockProvider(model, sleep=asyncio.sleep)
    client = EnrichmentClient(
        [ProviderBudget(provider=provider, rate=UNPACED, daily_limit=None)],
        cache=cache,
        quota=quota,
        hedge=hedge,
        clock=time.monotonic,
    )

    # Every lookup is a miss, so every one reaches the provider and the latency
    # distribution is measured rather than the cache's. Measuring hedging
    # through a cache would report the cache.
    indicators = sorted({indicator for _, indicator in timed})
    started = time.perf_counter()
    await client.enrich_many(indicators, concurrency=64)
    wall = time.perf_counter() - started
    cache.close()

    stats = client.stats
    return {
        "lookups": stats.requested,
        "provider_requests": stats.provider_requests,
        "hedges_sent": stats.hedges_sent,
        "hedges_won": stats.hedges_won,
        "p50_ms_simulated": round(stats.percentile(0.50), 1),
        "p90_ms_simulated": round(stats.percentile(0.90), 1),
        "p95_ms_simulated": round(stats.percentile(0.95), 1),
        "p99_ms_simulated": round(stats.percentile(0.99), 1),
        "max_ms_simulated": round(stats.percentile(1.0), 1),
        "wall_seconds": round(wall, 2),
    }


def lookups_per_day(daily_limit: int, requests_per_1000: float) -> float | None:
    """How many lookups a daily allowance supports at a measured request rate.

    The number that decides whether a free tier is usable at all. Uncached it
    is the allowance itself; cached it is the allowance divided by the share of
    lookups that still cost a request.
    """
    if requests_per_1000 <= 0:
        # Not infinity. A run in which nothing reached the provider means the
        # measurement did not happen, and reporting an unbounded capacity for
        # it would turn a broken run into the best result in the table.
        return None
    return daily_limit * 1000 / requests_per_1000


def _rounded(value: float | None) -> int | None:
    return None if value is None else round(value)


async def experiment_quota(workspace: Path, sizes, alpha: float, universe_ratio: float) -> list[dict]:
    results = []
    vt = preset("virustotal-public")
    for size in sizes:
        universe = max(10, int(size * universe_ratio))
        spec = StreamSpec(length=size, universe=universe, alpha=alpha)
        timed = generate_timed(spec)
        room = fresh(workspace / f"quota-{size}")
        measured = await replay_quota(timed, workspace=room)
        results.append(
            {
                "stream": {
                    **describe([indicator for _, indicator in timed]),
                    **describe_arrivals(timed),
                    "duration_days": round(spec.duration_seconds / 86_400, 2),
                },
                "alpha": alpha,
                "universe": universe,
                **measured,
                "virustotal_public_lookups_per_day": _rounded(
                    lookups_per_day(vt.daily_limit, measured["requests_per_1000_lookups"])
                ),
                "virustotal_public_lookups_per_day_uncached": vt.daily_limit,
            }
        )
        print(
            f"  {size:>8,} lookups over {measured['simulated_days_elapsed']:>5.1f}d  "
            f"hit {measured['cache_hit_rate']:.3f}  coalesced {measured['coalesced']:>6,}  "
            f"requests/1000 {measured['requests_per_1000_lookups']:>6.1f}  "
            f"{measured['lookups_per_wall_second']:>7,} lookups/s"
        )
    return results


async def experiment_ttl(workspace: Path, size: int, alpha: float, universe_ratio: float) -> list[dict]:
    universe = max(10, int(size * universe_ratio))
    timed = generate_timed(StreamSpec(length=size, universe=universe, alpha=alpha))
    policies = {
        "per_class_defaults": TTLPolicy(),
        "uniform_1h": TTLPolicy.uniform(3600.0),
        "uniform_4h": TTLPolicy.uniform(4 * 3600.0),
        "uniform_24h": TTLPolicy.uniform(24 * 3600.0),
        "uniform_7d": TTLPolicy.uniform(7 * 24 * 3600.0),
    }
    results = []
    for name, policy in policies.items():
        room = fresh(workspace / f"ttl-{name}")
        measured = await replay_quota(timed, workspace=room, ttl=policy)
        results.append({"policy": name, **measured})
        print(
            f"  {name:<20} hit {measured['cache_hit_rate']:.3f}  "
            f"requests/1000 {measured['requests_per_1000_lookups']:>6.1f}"
        )
    return results


async def experiment_hedging(workspace: Path, size: int, alpha: float, universe_ratio: float) -> list[dict]:
    universe = max(10, int(size * universe_ratio))
    timed = generate_timed(StreamSpec(length=size, universe=universe, alpha=alpha))
    model = LatencyModel()
    settings = {
        "off": HedgePolicy(enabled=False),
        "after_400ms": HedgePolicy(enabled=True, after_seconds=0.4, min_remaining_fraction=0.0),
        "after_800ms": HedgePolicy(enabled=True, after_seconds=0.8, min_remaining_fraction=0.0),
        "after_1500ms": HedgePolicy(enabled=True, after_seconds=1.5, min_remaining_fraction=0.0),
    }
    results = []
    baseline = None
    for name, policy in settings.items():
        room = fresh(workspace / f"hedge-{name}")
        measured = await replay_latency(timed, workspace=room, hedge=policy, model=model)
        if baseline is None:
            baseline = measured
        entry = {
            "policy": name,
            **measured,
            "extra_requests_vs_off": measured["provider_requests"] - baseline["provider_requests"],
            "extra_request_percent": round(
                (measured["provider_requests"] - baseline["provider_requests"])
                / baseline["provider_requests"]
                * 100,
                2,
            ),
            "p99_change_percent": round(
                (measured["p99_ms_simulated"] - baseline["p99_ms_simulated"])
                / baseline["p99_ms_simulated"]
                * 100,
                1,
            ),
        }
        results.append(entry)
        print(
            f"  {name:<13} p50 {measured['p50_ms_simulated']:>7.1f}  p95 {measured['p95_ms_simulated']:>7.1f}  "
            f"p99 {measured['p99_ms_simulated']:>7.1f}  requests {measured['provider_requests']:>6,} "
            f"(+{entry['extra_request_percent']:>5.2f}%)  p99 {entry['p99_change_percent']:>+6.1f}%"
        )
    return results


async def main_async(args) -> int:
    workspace = Path(args.workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    reference = StreamSpec(length=1, universe=1)

    print(f"A. quota efficiency (alpha={args.alpha}, universe = {args.universe_ratio:.0%} of stream)")
    quota_results = await experiment_quota(workspace, args.sizes, args.alpha, args.universe_ratio)

    print("\nB. cache lifetime policy")
    ttl_results = await experiment_ttl(workspace, args.ttl_size, args.alpha, args.universe_ratio)

    print("\nC. hedging (latencies simulated, request counts real)")
    hedge_results = await experiment_hedging(workspace, args.hedge_size, args.alpha, args.universe_ratio)

    document = {
        "note": (
            "Experiments A and B are real measurements of the caching algorithm on a generated stream "
            "whose distribution is documented in benchmark/stream.py; they involve no latency model at "
            "all. Experiment C's latency figures are a simulation, there is no API behind them, and they "
            "are only as good as the model recorded below, which is why every latency key is suffixed "
            "_simulated. The request counts in experiment C are real."
        ),
        "stream_model": {
            "alpha": args.alpha,
            "universe_ratio": args.universe_ratio,
            "class_mix": reference.mix,
            "duration_days": round(reference.duration_seconds / 86_400, 2),
            "burst_size_mean": reference.burst_size_mean,
            "burst_spread_seconds": reference.burst_spread_seconds,
            "coalescing_window_seconds": WINDOW_SECONDS,
            "indicators_drawn_independently_of_burst": (
                "Members of a burst draw indicators independently from the Zipf distribution rather than "
                "sharing a dominant one. A real scan burst is dominated by the indicator that caused it, "
                "so this understates coalescing rather than flattering it."
            ),
        },
        "latency_model_simulated": asdict(LatencyModel()),
        "quota_efficiency": quota_results,
        "ttl_policy": ttl_results,
        "hedging": hedge_results,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {args.out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", type=int, nargs="+", default=[10_000, 100_000])
    parser.add_argument("--ttl-size", type=int, default=50_000)
    parser.add_argument("--hedge-size", type=int, default=8_000)
    parser.add_argument("--alpha", type=float, default=1.1)
    parser.add_argument("--universe-ratio", type=float, default=0.2)
    parser.add_argument("--workspace", default="/tmp/iec-bench")
    parser.add_argument("--out", type=Path, default=ROOT / "docs" / "metrics.json")
    args = parser.parse_args(argv)
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
