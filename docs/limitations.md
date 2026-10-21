# What this does not do

Each entry says what would trigger building it, so the list is a set of
decisions rather than a set of excuses.

## A shared quota ledger

The ledger is a SQLite file. Two workers pointed at the same file coordinate
correctly, because the write path takes the lock before it counts. Two workers
on different volumes do not, and will each spend the full allowance of a key
they share.

This is the limitation to fix first, ahead of the shared cache below. Two
workers sharing a key already share an allowance, so the ledger has to be
shared before the cache does, and getting that ordering backwards means a
distributed cache that still gets the key suspended.

**Trigger:** a second worker that cannot see the first one's volume.

## A shared cache

The `Cache` protocol is narrow on purpose, so a distributed backend is a swap
rather than a rewrite. Until then, two workers each hold their own cache and
each miss on indicators the other has already fetched, at which point a per
worker cache has stopped being a cache and become two.

**Trigger:** the same second worker. See [ADR-002](adr/adr-002-sqlite-not-redis.md)
for why that trigger is a second worker rather than a traffic volume.

## Lifetime from the verdict rather than the class

A harmless verdict going stale is what costs a detection; a malicious one going
stale costs nothing, because nobody ever regretted treating a known bad
indicator as bad for an extra week. So lifetimes arguably belong on the
disposition and not only on the indicator class, and that is a better idea than
the one implemented.

It needs evidence about how often a harmless verdict flips, which this project
does not have. [ADR-001](adr/adr-001-cache-lifetime.md) is explicit that no
replay of an indicator stream can supply it: the stream records what was looked
up, not what the answer would have been at other times.

**Trigger:** a corpus of verdicts for the same indicators over time, from which
a flip rate can be measured rather than assumed.

## Freshness from the provider

Both providers return information about when they last analysed an indicator,
which is a better freshness signal than any policy in this library. Not used,
because it makes the cache depend on the shape of a response field outside this
project's control, and doing that defensively is a larger change than it looks.

**Trigger:** a second opinion on how stable those fields are, or a provider
whose published contract covers them.

## Retries

There are none. A provider error is reported, not retried. A retry on a metered
API is a second request, so it belongs to the same budget as a hedge and
deserves the same treatment: a policy with a quota floor, rather than a loop.
The structure for that exists, in `hedging.py`, and has not been generalised.

What the library does instead is make a single failure cheap to handle: the
error reaches every coalesced waiter from one attempt rather than each of them
retrying, and a partial answer from one provider is returned rather than
discarded because another failed.

**Trigger:** a provider whose documented error rate makes one attempt
insufficient, measured rather than assumed.

## Rate limit reconciliation from response headers

`Retry-After` is read where a provider sends it, in the delay seconds form.
Nothing adjusts the token bucket from a provider's own remaining quota headers,
which would be the only source of truth belonging to the caller rather than to
a preset in this repository.

Not implemented because the header names differ per provider and this library
should not assert what they are without having read each contract.
`docs/sources.md` records which figures came from documentation and which are
this library's own choice.

**Trigger:** a provider whose documentation specifies its rate limit headers,
at which point reconciliation can be written against a contract.

## Indicator classes beyond four

Addresses, file hashes, domains and URLs. No IPv6, no email addresses, no
registry keys, no mutexes. IPv6 is the obvious gap and is absent because the
classifier would need to handle its many textual forms, and an indicator sorted
into the wrong class gets the wrong cache lifetime and goes to a provider that
cannot answer it.

**Trigger:** IPv6 on first request. The others on evidence anyone enriches
them.

## Submitting anything

Both provider clients are read only by construction: no upload, no report, no
vote. That is not a limitation to be fixed. An analyst calling an enrichment
function does not expect a copy of a customer's file to leave the building, or
their own egress address to be published as an abuser.

**Trigger:** none. A separate library, if anyone wants one.
