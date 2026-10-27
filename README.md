# intel-enrichment-cache

[![CI](https://github.com/nilay-dave/intel-enrichment-cache/actions/workflows/ci.yml/badge.svg)](https://github.com/nilay-dave/intel-enrichment-cache/actions/workflows/ci.yml)
[![coverage](https://img.shields.io/endpoint?url=https://nilay-dave.github.io/intel-enrichment-cache/badges/coverage.json)](https://nilay-dave.github.io/intel-enrichment-cache/)
[![PyPI](https://img.shields.io/pypi/v/intel-enrichment-cache)](https://pypi.org/project/intel-enrichment-cache/)
[![python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![dependencies](https://img.shields.io/badge/runtime%20dependencies-1-green)](pyproject.toml)
[![licence](https://img.shields.io/badge/licence-MIT-green)](LICENSE)

A threat intelligence client for a SOAR worker, built around the constraint
that actually bites: a free tier allows a few hundred lookups a day, and an
alert pipeline produces more than that before lunch.

```bash
pip install intel-enrichment-cache
```

```python
from iec import EnrichmentClient, ProviderBudget, SqliteCache, VirusTotal, preset

client = EnrichmentClient(
    [ProviderBudget.from_preset(VirusTotal(api_key), preset("virustotal-public"))],
    cache=SqliteCache("intel-cache.sqlite"),
    quota="intel-quota.sqlite",
)

result = await client.enrich("8.8.8.8")
print(result.disposition, result.source)  # Disposition.HARMLESS Source.PROVIDER
```

## What it is for

On VirusTotal's public tier, 500 requests a day, an uncached client enriches
500 indicators a day and then stops. Measured over
<!--number:quota_efficiency[1].lookups-->100000<!--/number--> lookups from a
documented stream, this one brings the request rate down to
<!--number:quota_efficiency[1].requests_per_1000_lookups-->322.5<!--/number-->
per thousand, so the same allowance covers about
<!--number:quota_efficiency[1].virustotal_public_lookups_per_day-->1550<!--/number-->
lookups a day instead.

That is the whole claim. Everything below is how, and
[docs/measurements.md](docs/measurements.md) is the evidence, including which
figures are simulated.

## The five stages

Each is cheaper than the one behind it, and exists to stop work reaching it.

| stage | costs | stops |
| --- | --- | --- |
| cache | a local read | repeats, most of a skewed stream |
| coalescing | a dictionary lookup | duplicates that are in flight rather than stored |
| quota ledger | a SQLite write | anything leaving the process once the allowance is spent |
| token bucket | a wait | the short window limit being breached |
| provider | a request | nothing. This is the thing being rationed |

`client.stats` reports each separately. Coalescing is deliberately not counted
as a cache hit: a cache hit means somebody already asked and the answer was
stored, a coalesced call means somebody is asking right now, and on a bursty
stream those are not the same size.

## Three things worth knowing before using it

**An error is never cached.** An error is a fact about the network, not about
the indicator. Caching one pins a transient failure to that indicator for the
length of a lifetime, during which it reads as unresolved, which is the quiet
way a detection gets lost. `Disposition.UNKNOWN`, meaning the provider answered
and had nothing, *is* cached, with its own shorter lifetime.

**A partial answer is returned, not discarded.** Two providers, one times out
and the other answers: you get the answer with the failure recorded in
`result.error`. An analyst holding one verdict and a note about the other source
is better served than one holding an exception, and throwing away good data
because a different request failed also throws away quota already spent.

**The worst verdict wins.** Merging is by severity, not consensus and not a
mean. One provider calling an address malicious while another has never heard
of it is not a tie, and averaging a verdict with the absence of one produces a
number that means nothing.

## Rate limits are configuration, not facts

```python
from iec import Rate, ProviderBudget, preset

preset("virustotal-public")  # 4/minute, 500/day, with its source and the date read
ProviderBudget(provider=vt, rate=Rate(1000, 60.0), daily_limit=50_000)  # your own tier
```

A library that hardcodes a provider's limits is wrong the moment the provider
changes a tier, and was never right for a user on a different one. Every preset
carries the documentation it was read from, the date, and
`verify_against_your_account`, because none of them can be checked from inside
this library. Where a figure is this library's own conservative choice rather
than a published one, the preset's `note` says so.
[docs/sources.md](docs/sources.md) is the full accounting.

## Cache lifetimes depend on the indicator class

A file hash verdict changes when a vendor re-scans the sample, which is weeks.
An address reputation changes when a host is cleaned up or newly compromised,
which is hours, and a stale clean verdict on an address is the most expensive
wrong answer this library can give.

```python
from iec import TTLPolicy, IndicatorClass

TTLPolicy()                                    # 7d hashes, 12h domains, 6h urls, 4h addresses
TTLPolicy.uniform(24 * 3600)                   # one lifetime for everything
TTLPolicy(by_class={IndicatorClass.IP_ADDRESS: 900, ...})
```

The honest part: a uniform seven day lifetime scores a
<!--number:ttl_policy[4].cache_hit_rate-->0.889<!--/number--> hit rate against
<!--number:ttl_policy[0].cache_hit_rate-->0.643<!--/number--> for these
defaults, at roughly a third of the requests. On hit rate alone the per class
policy loses decisively. Hit rate is the wrong criterion, and
[ADR-001](docs/adr/adr-001-cache-lifetime.md) is the argument, published with
the measurement that goes against it.

## Hedging spends quota, so it is opt in

```python
from iec import HedgePolicy

HedgePolicy(enabled=True, after_seconds=0.4, min_remaining_fraction=0.25)
```

A hedge is a duplicate request sent when the first one is slow, and on a
metered API it is a request. It clears three gates: the first is still
outstanding, a token is free without waiting, and enough of the daily allowance
remains. Below the floor it is refused, because the last of the budget belongs
to alerts with no answer at all rather than to a faster answer for one already
on its way.

This module's docstring used to argue that made hedging expensive. The
benchmark disagreed: a hedge only fires on a request that has already stalled,
so its cost is bounded by the stall rate, not the traffic. At the modelled 2%
stall rate, hedging after 400ms cut the simulated p99 by
<!--number:hedging[1].p99_change_percent--> -74.3<!--/number-->% for
<!--number:hedging[1].extra_request_percent-->5.7<!--/number-->% more requests.
The docstring now says so, and it is still off by default, because 5% a caller
did not ask for is still 5% and the stall rate belongs to somebody else's
service.

## One runtime dependency

`httpx`. Async HTTP with timeouts is not worth writing, and nothing else here
is worth a dependency: the cache and the quota ledger are SQLite from the
standard library, the models are dataclasses, and
`tools/check_dependencies.py` fails the build on a declared dependency nothing
imports.

The cache and the ledger share one store on purpose
([ADR-002](docs/adr/adr-002-sqlite-not-redis.md)). A distributed backend goes
behind the narrow `Cache` protocol the moment a second worker exists, and the
ledger has to be shared before the cache does, because two workers sharing a
key already share an allowance.

## Testing code that uses this

```python
from iec.testing import VirtualClock
```

No test in this repository reaches a network or needs an API key; HTTP is
mocked with `respx` and CI fails a test that names a provider host without it.
Anything involving time uses the shipped virtual clock, whose docstring
explains why the obvious four line version of it is wrong. The benchmark wrote
that four line version anyway and reported hedging as having no effect, which
is in [ADR-003](docs/adr/adr-003-benchmark-harness.md) along with the other
three ways the benchmark was wrong before it was believable.

## What it does not do

A shared quota ledger, a shared cache, retries, lifetimes from the verdict,
freshness from the provider, IPv6. Each with the condition that would trigger
building it, in [docs/limitations.md](docs/limitations.md).

It also cannot submit anything. Both provider clients are read only by
construction: no upload, no report, no vote. That is not a limitation to fix.

## Development

```bash
make install
make verify      # everything CI runs, in the same order
make bench       # regenerate docs/metrics.json, takes a few minutes
make stream      # just the properties of a generated stream
```

## Licence

MIT.
