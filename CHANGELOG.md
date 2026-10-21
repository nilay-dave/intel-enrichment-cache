# Changelog

Kept by hand, in the format of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
following [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A change to a cache lifetime default, a disposition threshold or a rate preset
is a minor version at least. Those decide how much quota a caller spends and
what verdict they get back, so a patch release is the wrong place for them even
when the diff is one number.

## [Unreleased]

## [0.1.0]

First release.

### Added

- An enrichment client with five stages, each cheaper than the next: cache
  read, concurrent duplicate collapsing, durable quota check, token bucket,
  request.
- A token bucket that stays concurrent under contention, by reserving a slot
  rather than holding a lock across its sleep.
- A daily quota ledger counted over a rolling window and kept on disk, so a
  worker restart does not forget what it spent.
- Per indicator class cache lifetimes, with errors never cached and unknown
  answers given their own shorter lifetime.
- Request coalescing, counted separately from cache hits because on a bursty
  stream the two are not the same size.
- Quota aware hedging, off by default, refused when the daily allowance is low
  or no token is free.
- Read only VirusTotal and AbuseIPDB clients. Neither can upload or report.
- Rate presets carrying the documentation they were read from and the date.
- `iec.testing.VirtualClock`, used by the test suite and the benchmark.

### Measured

Real, from experiments involving no latency model:

- 100,000 lookups over a simulated week: 0.676 cache hit rate, 322 provider
  requests per 1,000 lookups.
- A uniform seven day cache lifetime reaches a 0.873 hit rate against 0.572 for
  the per class defaults, which is the measurement
  [ADR-001](docs/adr/adr-001-cache-lifetime.md) publishes against its own
  conclusion.

Simulated, from the latency model in `benchmark/mock_provider.py`:

- Hedging after 400ms cut the simulated p99 by 73% for 5.4% more requests.

### Known limitations

A shared quota ledger, a shared cache, retries, lifetime from the verdict,
freshness from the provider, IPv6. Each with the condition that would trigger
building it, in `docs/limitations.md`.
