# Contributing

## Running everything CI runs

```bash
make install
make verify
```

`verify` runs the same checks as CI, in the same order. A verify that is a
subset of CI is a verify that lies.

## The tests never touch a network

No API key, no outbound request, no live provider. A library whose tests need
credentials is one nobody can contribute to, and one whose tests hit a real
provider spends somebody's free tier on every CI run.

HTTP is mocked with `respx`. If you add a test that names a provider host, mock
the transport in the same file; CI fails on a test that names
`www.virustotal.com` or `api.abuseipdb.com` without importing `respx`.

## Testing anything that involves time

Use `iec.testing.VirtualClock`, not `asyncio.sleep` with small numbers.

The rate limiter's interesting behaviour all lives at the boundary of a window,
and a test against the real clock gives you a choice between a suite that takes
minutes and an assertion weaker than the limit it is checking. The clock's own
docstring explains why the obvious four line version of it is wrong; the short
answer is that a counter which each sleep advances by its own duration
serialises concurrent sleeps, so a limiter appears to refill while callers
wait.

A test whose pass depends on a real millisecond margin will pass alone and fail
in the full suite, where the margin disappears under load. One of these already
did. If a test needs "this finished before that", make it structurally true
with an `Event` rather than numerically likely with a sleep.

## Adding a provider

Four things.

**Implement the `Provider` protocol**: a `name`, a `supports` set of indicator
classes, and `lookup`. Declare `supports` honestly: the client uses it to avoid
spending a request to learn that an endpoint cannot answer a hash.

**Raise rather than return an error disposition.** A failure has to travel as
an exception, because returning one would let a transient network problem be
cached as a fact about the indicator, after which the indicator reads as
unresolved for the length of a lifetime.

**Use `RateLimited` for a 429 and `ProviderError` for everything else.**
Reaching a 429 means the local limiter was wrong, which calls for fixing a
preset. A 500 means the provider is unwell, which calls for the opposite. They
are separate types so a caller can tell them apart.

**Parse defensively.** A response shape that changes should degrade to
`UNKNOWN`, not raise a `KeyError` from the middle of an enrichment. `UNKNOWN`
is honest there: the client genuinely does not know what the provider said.

Add a preset only if you have read the vendor's documentation, and record the
source and the date on it. If a figure in the preset is your own conservative
choice rather than the vendor's published number, say so in the `note`; there
is a test asserting that label is present on the ones that are.

## Measuring anything

`make bench` regenerates `docs/metrics.json`.

Keep the two kinds of number apart. Request counts, hit rates and coalescing
counts are real properties of the algorithm and must not be produced through
the latency model. Latency figures come from a simulation, every key carrying
one is suffixed `_simulated`, and the suffix is not optional.

Read [ADR-003](docs/adr/adr-003-benchmark-harness.md) before changing the
harness. It lists the four ways this benchmark was wrong before it was
believable, three of which produced plausible numbers rather than crashes.

## House style

**No em dashes or en dashes.** Commas, colons and parentheses. `make verify`
checks at the Unicode code point level over every git tracked file.

**Escape pipes inside markdown table cells.** `tools/check_tables.py` catches
an unescaped one, which silently produces a table with the wrong number of
columns.

**One runtime dependency.** `httpx`, because async HTTP with timeouts is not
worth writing. `tools/check_dependencies.py` fails the build on a declared
dependency nothing imports. A second runtime dependency needs an ADR.

**Published numbers carry a marker.** Any measured figure in the README or in
`docs/` is tagged:

```
<!--number:quota_efficiency[0].cache_hit_rate-->0.544<!--/number-->
```

`tools/check_numbers.py` compares it against `docs/metrics.json`. A number with
no marker is a number nobody is checking, which is why the throughput figures
are deliberately rounded and unmarked: they move between runs, and a marker on
a figure that moves fails builds for no reason.

**A per call fact is returned, not inferred from a counter.** This has been
got wrong twice in this repository, in the coalescer and in the hedger. Both
compared a shared counter before and after, which under concurrency attributes
other calls' work to this one, and both produced counts that were arithmetically
impossible before anyone noticed. If you need to know what one call did, have
it tell you.

**Verify and commit are two steps.** Never `pytest && git commit`. Run the
tests, read the output, then commit.

## Commits

Conventional Commits, verified by `tools/check_commit_subject.py` as a
`commit-msg` hook:

```bash
ln -s ../../tools/check_commit_subject.py .git/hooks/commit-msg
```

The subject says what changed; the body says why, and what was tried and
rejected.
