# ADR-001: Lifetime per indicator class, and the measurement that argues against it

Status: accepted
Date: 2026-10-21

## Context

A cached verdict is useful until it is wrong. How long that takes depends on
what kind of thing was looked up: a file hash verdict changes when a vendor
re-scans the sample, which is days or weeks, while an address reputation
changes when a host is cleaned up or newly compromised, which is hours.

The planned decision was per class lifetimes over a single global one, and the
planned justification was a measured hit rate. The measurement was run and
argues the other way.

## What was measured

10,000 lookups over a simulated week, drawn from a Zipf distribution with alpha
1.1 over a universe one fifth the length of the stream, arriving in bursts.
Full parameters in `benchmark/stream.py`; every figure reproduces with
`make bench`.

| lifetime policy | cache hit rate | provider requests per 1,000 lookups |
| --- | --- | --- |
| per class defaults | 0.572 | 422 |
| uniform 1 hour | 0.393 | 586 |
| uniform 4 hours | 0.554 | 438 |
| uniform 24 hours | 0.732 | 266 |
| uniform 7 days | 0.873 | 127 |

A uniform seven day lifetime beats the per class policy on hit rate by a wide
margin, and costs a third of the requests. On the criterion the measurement was
designed to settle, per class loses decisively.

## Decision

Per class lifetimes, with the measurement published next to it.

Hit rate is the wrong criterion, and running the measurement is what made that
obvious. A longer lifetime always produces a better hit rate, right up to a
policy of never expiring anything, which would score perfectly and be useless.
What the table measures is not whether the policy is good; it is the price of
the policy.

The thing hit rate cannot see is which wrong answers each policy produces. A
seven day old harmless verdict on an address that was compromised yesterday is
the single most expensive wrong answer this library can give, because it is
indistinguishable from a fresh one and it suppresses a real detection in
silence. A seven day old verdict on a file hash is usually still true.

So the decision rests on a judgement the benchmark cannot make, and the
benchmark's job is to say what the judgement costs: 422 requests per thousand
lookups instead of 127, which is 3.3 times the quota, in exchange for never
serving an address reputation more than four hours old.

## Consequences

A team that disagrees can disagree concretely. `TTLPolicy` takes a dictionary,
`TTLPolicy.uniform` exists specifically so the comparison in the table above is
one line to reproduce, and a team willing to accept day old address reputations
knows from this table what it buys them.

The defaults themselves are reasoning rather than measurement, and the module
docstring says so. Nothing in a replayed indicator stream can reveal how long a
verdict stays true, because the stream records what was looked up and not what
the answer would have been at other times. Measuring that needs a corpus of
verdicts over time, which this project does not have and does not pretend to.

An unknown answer gets its own, shorter lifetime, for a different reason:
caching it at all matters because on a long tailed stream the indicators nobody
has heard of are where the quota goes, and expiring it sooner matters because
an indicator nobody knows today may be known tomorrow, which is the case where
staleness costs a detection rather than just a request.

## Alternatives considered

**One global lifetime.** Simpler, measurably better on hit rate, and wrong for
the reason above. A single value is either too short for hashes, which wastes
the quota the cache exists to save, or too long for addresses, which is the
dangerous direction.

**Lifetime from the verdict rather than the class.** Expire a malicious verdict
slowly and a harmless one quickly, since a harmless verdict going stale is what
costs a detection. This is a better idea than the one implemented and is not
implemented: it needs evidence about how often a harmless verdict flips, which
is the measurement this project does not have. Recorded in
`docs/limitations.md` with the condition that would trigger it.

**Lifetime from provider supplied freshness.** Both providers return
information about when they last analysed an indicator, which is a better
signal than any policy here. Rejected for this version only because it makes
the cache depend on a response field whose shape is outside this project's
control, and the defensive parsing that would need is a larger change than it
looks.
