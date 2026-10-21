# Where the numbers come from

Three kinds of figure appear in this repository, and they are not equally
trustworthy. Keeping them apart is the point of this file.

## Documented limits, read from the vendor

| figure | source | read on |
| --- | --- | --- |
| VirusTotal public API: 4 requests per minute, 500 per day | docs.virustotal.com, public versus premium API | 2026-10-21 |
| AbuseIPDB standard plan, CHECK endpoint: 1,000 per day | docs.abuseipdb.com, rate limits | 2026-10-21 |
| AbuseIPDB standard plan, REPORTS endpoint: 100 per day | docs.abuseipdb.com, rate limits | 2026-10-21 |

Each is attached to its preset in `src/iec/limits/presets.py` with the source
and the date, so a reader who wants to know whether a figure is still true
knows where to look. Every preset also carries
`verify_against_your_account`, because none of them can be checked from inside
this library and a caller on a paid tier has different numbers entirely.

## This library's own choices, labelled as such

AbuseIPDB documents a daily limit for these endpoints and no short window one.
The per minute pacing in those presets, 10 for CHECK and 5 for REPORTS, is this
library being conservative, not a number the vendor published. Presenting it as
theirs would be inventing a fact about somebody else's API, so the preset's
note says so and a test asserts the label is present.

The disposition thresholds are also choices: two engines for malicious, one for
suspicious, 75 and 25 on AbuseIPDB's confidence scale. The reasoning is in
`providers/base.py` and they are configurable, because a team that buries its
analysts on single engine detections should be able to move the line without
forking.

The cache lifetime defaults are reasoning rather than measurement, and
[ADR-001](adr/adr-001-cache-lifetime.md) is explicit that the measurement which
would settle them does not exist in this project.

## Measurements, and which of them are simulated

`docs/metrics.json` carries a `note` field recording this, and every key
derived from the latency model is suffixed `_simulated`.

**Real.** Cache hit rates, coalescing counts, provider request counts, and
everything derived from them including requests per thousand lookups and the
lookups per day a free tier supports. These are properties of the algorithm on
a stated stream. No part of them depends on a latency model, which is why the
experiments that produce them use no latency at all.

**Simulated.** Every latency percentile. There is no API behind them. They come
from the lognormal plus stall tail model in `benchmark/mock_provider.py`, whose
parameters are recorded in the metrics file, and they are only as good as that
model. The p99 improvement hedging shows is a statement about the model, not a
promise about VirusTotal.

**Real, inside the simulated experiment.** The request counts in the hedging
experiment. This matters: hedging's cost is paid in requests and its benefit
only in latency, so the half of that trade which is measured rather than
modelled is the cost.

## The stream the measurements run on

Generated, not captured, with every parameter in `benchmark/stream.py`: a Zipf
repeat distribution at alpha 1.1 over a universe one fifth the stream's length,
arriving in bursts over a simulated week.

It is a model of alert traffic and not anybody's alert traffic. One choice in
it is deliberately conservative: members of a burst draw their indicators
independently rather than sharing a dominant one, where a real scan burst is
dominated by the indicator that caused it. That understates coalescing rather
than flattering it.

A reader wanting their own numbers should replay their own indicator log. That
is what `stream.load()` is for, and it is one line in the benchmark.
