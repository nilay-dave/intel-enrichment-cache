"""What a cache has to do, and what the TTL defaults are.

The TTL defaults are judgement, not measurement, and are labelled that way. No
amount of replaying an indicator stream can tell you how long a verdict stays
true, because the stream contains the indicators that were looked up and not
what the answers would have been at other times. What the measurements in
ADR-001 can show is the consequence of a choice: the hit rate and the quota a
given set of TTLs produces on a documented stream, and how a single global TTL
compares with per class ones. That is the part worth measuring and the part
worth publishing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from iec.models import Disposition, Enrichment, IndicatorClass

# Hours, chosen on how fast each class of answer goes stale. Reasoning rather
# than measurement, which is why they are overridable and why ADR-001 argues
# the shape of the policy rather than these particular numbers.
#
# A file hash verdict changes when a vendor re-scans the sample, which is days
# or weeks. An address reputation changes when a host is cleaned up or newly
# compromised, which is hours, and a stale clean verdict on an address is the
# most expensive kind of wrong answer this library can give. A domain sits
# between the two. A URL is treated as shorter than its domain, because a path
# can be weaponised on a host whose reputation has not moved yet.
DEFAULT_TTL_SECONDS: dict[IndicatorClass, float] = {
    IndicatorClass.FILE_HASH: 7 * 24 * 3600.0,
    IndicatorClass.IP_ADDRESS: 4 * 3600.0,
    IndicatorClass.DOMAIN: 12 * 3600.0,
    IndicatorClass.URL: 6 * 3600.0,
}

# An answer of "no provider has heard of this" is worth caching, because on a
# long tailed stream the unknown indicators are where the quota goes. It gets
# its own, shorter lifetime: an indicator nobody knows today may be known
# tomorrow, and that is the case where being stale costs a detection.
DEFAULT_UNKNOWN_TTL_SECONDS = 3600.0


@dataclass(frozen=True)
class TTLPolicy:
    """How long each class of answer is kept."""

    by_class: dict[IndicatorClass, float] | None = None
    unknown_seconds: float = DEFAULT_UNKNOWN_TTL_SECONDS

    def seconds_for(self, kind: IndicatorClass, disposition: Disposition) -> float:
        if disposition is Disposition.UNKNOWN:
            return self.unknown_seconds
        table = self.by_class if self.by_class is not None else DEFAULT_TTL_SECONDS
        return table.get(kind, DEFAULT_TTL_SECONDS[kind])

    @classmethod
    def uniform(cls, seconds: float) -> TTLPolicy:
        """One lifetime for everything, which is what ADR-001 compares against."""
        return cls(by_class=dict.fromkeys(IndicatorClass, seconds), unknown_seconds=seconds)


@dataclass
class CacheStats:
    """Counted rather than derived, so the benchmark and the client agree."""

    hits: int = 0
    misses: int = 0
    expired: int = 0
    stores: int = 0
    rejected: int = 0

    @property
    def lookups(self) -> int:
        return self.hits + self.misses

    @property
    def hit_rate(self) -> float:
        return self.hits / self.lookups if self.lookups else 0.0


class Cache(Protocol):
    """The interface a backend has to satisfy.

    Narrow on purpose. The pivot recorded in the readme is that a distributed
    cache goes behind this interface the moment a second enrichment worker
    exists, and an interface with a SQLite shaped hole in it would make that a
    rewrite rather than a swap.
    """

    async def get(self, key: str) -> Enrichment | None:
        """The stored answer, or None for a miss or an expired entry."""
        ...

    async def put(self, enrichment: Enrichment, ttl_seconds: float) -> bool:
        """Store an answer. Returns False when the answer was not cacheable."""
        ...

    async def purge_expired(self) -> int:
        """Remove expired entries, returning how many went."""
        ...

    @property
    def stats(self) -> CacheStats:
        ...
