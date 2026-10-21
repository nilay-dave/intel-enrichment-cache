# ADR-003: One mechanism per experiment, not one harness for all of them

Status: accepted
Date: 2026-10-21

## Context

Three things needed measuring: how many provider requests a stream costs, what
a cache lifetime policy is worth, and what hedging buys and costs.

The first attempt drove all three through one general purpose virtual clock, on
the reasoning that a single harness is less code than three. It produced
numbers that were wrong in four distinct ways before any of them were
believable, and finding each one took longer than the measurement it was
blocking.

## What went wrong, in order

**No time passed, so lifetimes measured nothing.** The first version submitted
every alert at once. Virtual time then only advanced by the simulated request
latency, so a ten thousand alert replay covered about a minute, no cache entry
ever expired, and all five lifetime policies scored identically to three
decimal places. The table looked like a finding and was an artifact. Alerts now
carry arrival times spread over a week, in bursts, which is also what makes the
coalescing figure mean anything.

**The benchmark wrote its own clock, the wrong one.** This package ships a
virtual clock whose docstring explains at length why the naive version, a
counter that each sleep advances by its own duration, serialises concurrent
sleeps. The benchmark then wrote that exact naive version, and hedging measured
as having no effect at all, because nothing was ever still outstanding when a
hedge delay elapsed. The clock moved into the package so there is one of it.

**The clock could not drive code that touches disk.** A coroutine inside
`asyncio.to_thread`, which is how the cache reaches SQLite, is parked on a
future another thread will resolve rather than on virtual time, so the clock
had nothing to advance and no way to tell that from a deadlock. It raised on
the first replay with a deadlock report when the only thing happening was a
disk read. It now distinguishes the two by progress rather than by a timeout,
and takes an `activity` hook, because progress inside tasks it does not own,
which is what a run of cache hits is, was invisible to it.

**The workspace was reused, so a run inherited the last one's cache.** One run
served every lookup from a cache it had not populated, reported zero provider
requests, and the derived lookups per day came out as infinity. That is how the
bug announced itself; had the stream been slightly different it would have
reported a merely flattering number instead and been believed.

## Decision

Each experiment uses the simplest mechanism that answers its own question.

**Quota and lifetime experiments use no latency model and no virtual clock.** A
request count does not depend on how long a request takes. The stream is
replayed in arrival order, grouped into two second windows so the coalescer
sees concurrent arrivals, with the cache's clock set to each window so
lifetimes expire as days pass. Deterministic, and there is nothing in it to be
wrong about.

**The hedging experiment uses real asyncio and really sleeps the drawn
delays**, on a smaller sample, because it is the only one that needs time to
pass. The virtual clock stays in the package, where the unit tests use it to
check the rate limiter at window boundaries, which is what it is good at.

Every replay starts from an empty directory.

## Consequences

More code than one harness, and each piece is small enough to read in one
sitting. No experiment can be broken by a change made for a different one.

The honest cost: the hedging experiment now takes real wall clock time,
roughly one second of it per five hundred lookups at the modelled latency,
which is why it runs on a smaller sample than the others and why its
percentiles carry the sample size next to them.

## The general lesson, since it recurred

A benchmark whose scaffolding is harder to trust than the code under test is
not measuring anything. Three of the four faults above produced plausible
numbers rather than crashes: identical lifetime scores, hedging having no
effect, and an infinite capacity. Only the last was obviously absurd, and it
was obvious by luck.

The same mistake also appeared twice in the library itself, in a form this ADR
is the right place to name because it is the same error of reasoning. Both the
coalescer and the hedger originally reported per call facts by comparing a
shared counter before and after. Under concurrency that attributes other
calls' work to this one: a burst of 25 reported 25 coalesced lookups out of 25,
which is one more than can exist, and a hedging run reported 583 provider
requests for 217 lookups, which is more than one hedge each and so impossible.
Both now return what the call itself did. A counter delta is not a per call
measurement, and the fact that it reads like one is the whole problem.
