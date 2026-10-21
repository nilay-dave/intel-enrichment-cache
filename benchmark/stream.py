"""Generates an indicator stream whose repeat distribution is documented.

The shape of the stream decides every number this benchmark produces, so it is
stated rather than left in the code. A uniform stream over a large universe
makes a cache look useless; a stream of ten indicators makes it look perfect.
Neither resembles alert traffic.

Real alert streams are heavily skewed. A handful of addresses and hashes appear
in a large share of alerts, because scanning infrastructure, commodity malware
and the same misconfigured internal host account for most of the volume, while
a long tail appears once and never again. That is a Zipf shape, and the
parameter is the thing to argue with rather than hide: alpha near 1 is a
moderate skew, alpha above 1.5 is severe.

Arrivals matter as much as the repeat distribution, and the first version of
this file left them out. Dumping every alert into the client at once made two
of the three experiments measure nothing: no virtual time passed, so no cache
entry ever expired and every lifetime policy scored identically, and every
alert was concurrent, so the coalescing figure was an artifact of the harness
rather than a property of alert traffic.

So the stream carries a time. Alerts arrive in bursts, because that is what
alert traffic does: a scan or a mail campaign produces a cluster of alerts
within seconds, sharing indicators, and then nothing for a while. Bursts arrive
as a Poisson process over the duration, their sizes are geometric, and the
alerts inside one are spread across a few seconds. Coalescing then earns its
keep on the clusters, and lifetimes matter because days pass.

This is a model, not a capture. The hit rates it produces are real properties
of the caching algorithm on a stated distribution, and they are not a
prediction about anybody's SOC. A reader wanting their own number should replay
their own indicator log, which is what load() is for.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

# The mix across indicator classes. Chosen to be stated and arguable rather
# than accurate for any particular deployment: addresses dominate because
# network alerts outnumber endpoint alerts in most pipelines, and hashes are
# next because every process creation alert carries one.
DEFAULT_MIX = {
    "ip_address": 0.55,
    "file_hash": 0.30,
    "domain": 0.12,
    "url": 0.03,
}


@dataclass
class StreamSpec:
    """Everything that decides what the stream looks like.

    ``duration_seconds`` is what makes a cache lifetime mean anything: 10,000
    alerts over a week is roughly one a minute, which is a mid sized pipeline's
    enrichable volume, and a four hour lifetime expires many times over the
    course of it. The same 10,000 alerts delivered instantly would never expire
    a single entry.

    ``burst_size_mean`` is what makes coalescing mean anything. Alerts do not
    arrive one at a time: a scan or a campaign produces a cluster within
    seconds, sharing indicators.
    """

    length: int
    universe: int
    alpha: float = 1.1
    mix: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_MIX))
    seed: int = 7
    duration_seconds: float = 7 * 24 * 3600.0
    burst_size_mean: float = 8.0
    burst_spread_seconds: float = 2.0

    def __post_init__(self) -> None:
        if self.length <= 0 or self.universe <= 0:
            raise ValueError("length and universe must be positive")
        if self.alpha <= 0:
            raise ValueError("alpha must be positive")
        if self.duration_seconds <= 0:
            raise ValueError("duration_seconds must be positive")
        if self.burst_size_mean < 1:
            raise ValueError("burst_size_mean must be at least 1")
        if self.burst_spread_seconds < 0:
            raise ValueError("burst_spread_seconds must not be negative")
        total = sum(self.mix.values())
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"mix must sum to 1, got {total}")


def _rank_probabilities(universe: int, alpha: float) -> np.ndarray:
    ranks = np.arange(1, universe + 1, dtype=np.float64)
    weights = ranks ** (-alpha)
    return weights / weights.sum()


def _render(kind: str, index: int) -> str:
    """A syntactically valid indicator for a rank, deterministic in the rank."""
    if kind == "ip_address":
        # 10.x.y.z, which is a documentation range, so no generated indicator
        # is ever a real routable address somebody might look up for real.
        return f"10.{index // 65536 % 256}.{index // 256 % 256}.{index % 256}"
    if kind == "file_hash":
        return f"{index:064x}"
    if kind == "domain":
        return f"host{index}.invalid"
    if kind == "url":
        return f"https://host{index}.invalid/path/{index}"
    raise ValueError(f"unknown indicator class {kind!r}")


def arrival_times(spec: StreamSpec, rng: np.random.Generator) -> np.ndarray:
    """One arrival time per alert, clustered into bursts.

    Burst starts are uniform over the duration, which is a Poisson process of
    bursts. Sizes are geometric with the given mean, so a few bursts are large
    and most are small. Members of a burst are spread uniformly across
    burst_spread_seconds, which is what puts several alerts inside one
    coalescing window.
    """
    if spec.burst_size_mean <= 1.0:
        return np.sort(rng.uniform(0.0, spec.duration_seconds, size=spec.length))

    times: list[np.ndarray] = []
    produced = 0
    probability = 1.0 / spec.burst_size_mean
    while produced < spec.length:
        size = min(int(rng.geometric(probability)), spec.length - produced)
        start = rng.uniform(0.0, spec.duration_seconds)
        offsets = rng.uniform(0.0, spec.burst_spread_seconds, size=size)
        times.append(start + offsets)
        produced += size
    return np.sort(np.concatenate(times))[: spec.length]


def generate(spec: StreamSpec) -> list[str]:
    """Build the indicator sequence, without arrival times."""
    rng = np.random.default_rng(spec.seed)
    probabilities = _rank_probabilities(spec.universe, spec.alpha)

    kinds = list(spec.mix)
    weights = np.array([spec.mix[kind] for kind in kinds])
    # One class is drawn per distinct indicator rather than per occurrence, so
    # a given indicator keeps its class across every appearance. Drawing per
    # occurrence would turn one address into an address sometimes and a hash
    # other times, and the cache would then be keyed on something that cannot
    # happen.
    rank_kinds = rng.choice(len(kinds), size=spec.universe, p=weights)
    catalogue = [_render(kinds[rank_kinds[rank]], rank) for rank in range(spec.universe)]

    draws = rng.choice(spec.universe, size=spec.length, p=probabilities)
    return [catalogue[rank] for rank in draws]


def generate_timed(spec: StreamSpec) -> list[tuple[float, str]]:
    """Build the stream as (arrival time, indicator) pairs, sorted by time."""
    indicators = generate(spec)
    times = arrival_times(spec, np.random.default_rng(spec.seed + 1))
    return list(zip(times.tolist(), indicators, strict=True))


def describe_arrivals(timed: list[tuple[float, str]], window_seconds: float = 2.0) -> dict:
    """How clustered the arrivals are, which is what coalescing feeds on."""
    times = np.array([time for time, _ in timed])
    if times.size < 2:
        return {"alerts_per_hour": 0.0, "share_within_window_of_another": 0.0}
    gaps = np.diff(times)
    duration_hours = (times[-1] - times[0]) / 3600 or 1.0
    close = np.concatenate(([gaps[0]], np.minimum(gaps[:-1], gaps[1:]), [gaps[-1]]))
    return {
        "alerts_per_hour": round(len(times) / duration_hours, 2),
        "median_gap_seconds": round(float(np.median(gaps)), 3),
        "share_within_window_of_another": round(float((close <= window_seconds).mean()), 4),
    }


def describe(stream: list[str]) -> dict:
    """The properties of a generated stream, for the record alongside results."""
    counts = Counter(stream)
    occurrences = np.array(sorted(counts.values(), reverse=True))
    total = len(stream)
    return {
        "length": total,
        "distinct": len(counts),
        "repeat_rate": round(1 - len(counts) / total, 4),
        "top_1_share": round(float(occurrences[0]) / total, 4),
        "top_10_share": round(float(occurrences[:10].sum()) / total, 4),
        "top_100_share": round(float(occurrences[:100].sum()) / total, 4),
        "seen_once_share": round(float((occurrences == 1).sum()) / len(counts), 4),
    }


def load(path: Path) -> list[str]:
    """Read one indicator per line, so a reader can replay their own log."""
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--length", type=int, default=10_000)
    parser.add_argument("--universe", type=int, default=2_000)
    parser.add_argument("--alpha", type=float, default=1.1)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)

    spec = StreamSpec(length=args.length, universe=args.universe, alpha=args.alpha, seed=args.seed)
    timed = generate_timed(spec)
    stream = [indicator for _, indicator in timed]
    properties = {**describe(stream), **describe_arrivals(timed)}
    print(json.dumps(properties, indent=2))
    if args.out:
        args.out.write_text("\n".join(stream) + "\n", encoding="utf-8")
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
