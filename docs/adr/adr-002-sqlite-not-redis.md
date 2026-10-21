# ADR-002: SQLite for both the cache and the quota ledger

Status: accepted
Date: 2026-10-21

## Context

This library needs two pieces of durable state: the indicator cache and the
daily quota ledger. The quota ledger has to be durable rather than in memory,
because a worker that restarts and forgets what it spent will spend it again,
and the whole point of local accounting is to avoid learning the limit from the
provider. The cache does not strictly have to be durable, but a cache that
empties on every deploy spends a day's allowance refilling itself.

Redis is the reflexive answer and would work. So would a second store for one
of the two.

## Decision

SQLite, in WAL mode, for both.

## Consequences

One fewer service to run, monitor, back up, secure and explain. A SOAR worker
is often deployed as a container with a volume, and a library that requires a
Redis to be stood up before it can cache anything is a library that does not
get adopted for a week while somebody argues about where the Redis lives.

One store rather than two. The quota ledger and the cache have the same
durability needs and the same access pattern, and a second technology for the
second one would be a second thing to configure and get wrong.

WAL mode, so readers do not block the writer. Several workers against one
volume is common enough that the default rollback journal, where a write
excludes every reader, would make the cache the contention point it was added
to remove.

The quota ledger's write path uses `BEGIN IMMEDIATE` around the count and the
insert. Without it two workers can count the same free slot and both fill it,
which is the one place in this library where a race produces an over spend
rather than a wasted request.

Cache access goes through a thread, because SQLite's driver is blocking and a
coroutine that calls it stalls every other task in the worker. That is a
fraction of a millisecond on a local file and easy to shrug at, and it is not a
fraction of a millisecond when the file is on network storage or another
process holds the write lock. Connections are thread local, not one shared
behind a lock, which would serialise reads across the pool and defeat the point
of moving them off the loop.

## What the measurement says about the choice

The benchmark replays 10,000 lookups at roughly 1,100 lookups a second end to
end, through the cache, the coalescer and the quota ledger. At the volumes this
library is for, where a free tier allows 500 provider requests a day, the store
is not within an order of magnitude of being the constraint. The constraint is
the provider's allowance, which is the thing the cache exists to stretch.

That is the argument for SQLite being sufficient, and it is not an argument
that SQLite is faster than Redis. It is not.

## The pivot

The `Cache` protocol in `cache/store.py` is deliberately narrow: get, put,
purge, stats. A distributed backend goes behind it the moment a second
enrichment worker exists and the two start missing on indicators the other has
already fetched, which is the point at which a per worker cache stops being a
cache and becomes two.

The trigger is a second worker, not a volume of traffic. An interface with a
SQLite shaped hole in it would make that a rewrite rather than a swap, which is
why the protocol has no transaction, no connection and no path in it.

Note that the quota ledger does not have that interface and would need one.
Two workers sharing an API key already share an allowance, so the ledger has to
be shared before the cache does. That is the honest ordering and it is recorded
in `docs/limitations.md`.

## Alternatives considered

**Redis for both.** Rejected on operational cost at the target deployment size,
not on capability. It is the right answer at the second worker, which is what
the pivot above is for.

**In memory for the cache, SQLite for the ledger.** A faster cache that empties
on deploy. Rejected: a cold cache after every rollout spends a large share of a
free tier's daily allowance re-fetching answers it already had, which is the
cost this library exists to avoid.

**No ledger, rely on the provider's 429.** Rejected outright. It means learning
the limit by hitting it, the response to which is a request already spent, and
on some tiers repeated breaches are what gets a key suspended rather than
throttled.
