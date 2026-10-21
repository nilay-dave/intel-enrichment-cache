"""The types that cross the library's boundary.

An indicator's class is not decoration. It decides the cache lifetime, which
provider can answer, and whether a miss is worth a second request, so it is
part of the indicator rather than something a caller passes alongside it and
can forget.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

HASH_PATTERNS = {
    32: "md5",
    40: "sha1",
    64: "sha256",
}
IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
# The final label may not be entirely numeric. No top level domain is, and
# without that rule "1.2.3" and "192.168.1" are syntactically valid hostnames,
# so a truncated or mistyped address classifies as a domain and spends a request
# on an endpoint that can never resolve it. The error a caller gets back is then
# "no data held" rather than "that is not an indicator".
DOMAIN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.(?!-)(?!\d+$)[A-Za-z0-9-]{1,63}(?<!-)$"
)


class IndicatorClass(StrEnum):
    """What kind of thing is being looked up.

    The classes are separated by how fast their answer goes stale, which is the
    only distinction the cache cares about. A file hash verdict changes when a
    vendor re-scans; an address reputation changes when a host is cleaned up or
    compromised, and that is a different timescale entirely. ADR-001 has the
    measurements that set the defaults.
    """

    FILE_HASH = "file_hash"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"


class Disposition(StrEnum):
    """What the providers collectively said."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    HARMLESS = "harmless"
    UNKNOWN = "unknown"
    # Distinct from UNKNOWN. UNKNOWN means the provider answered and had
    # nothing; ERROR means nobody answered, which is not a fact about the
    # indicator and must never be cached as though it were.
    ERROR = "error"


class Source(StrEnum):
    """Where an answer came from, which is what the measurements count."""

    CACHE = "cache"
    # Served from another caller's in flight request rather than a new one. A
    # separate source because it saves quota exactly as a cache hit does, and
    # counting it as a cache hit would overstate what the cache achieves.
    COALESCED = "coalesced"
    PROVIDER = "provider"
    # Asked for, refused by the local quota accounting before any request was
    # sent. A caller needs to tell this apart from a provider error.
    QUOTA_EXHAUSTED = "quota_exhausted"


def classify(value: str) -> IndicatorClass:
    """Work out an indicator's class from its text.

    Raises ValueError rather than guessing. An indicator sorted into the wrong
    class gets the wrong cache lifetime and is sent to a provider that cannot
    answer it, and both failures are quiet.
    """
    text = value.strip()
    if not text:
        raise ValueError("indicator is empty")

    lowered = text.lower()
    if lowered.startswith(("http://", "https://")):
        return IndicatorClass.URL
    if IPV4.match(text):
        octets = [int(part) for part in text.split(".")]
        if all(0 <= octet <= 255 for octet in octets):
            return IndicatorClass.IP_ADDRESS
        raise ValueError(f"{value!r} looks like an IPv4 address with an octet out of range")
    if len(text) in HASH_PATTERNS and re.fullmatch(r"[0-9a-fA-F]+", text):
        return IndicatorClass.FILE_HASH
    if DOMAIN.match(text):
        return IndicatorClass.DOMAIN
    raise ValueError(f"cannot classify {value!r} as a hash, address, domain or url")


@dataclass(frozen=True)
class Indicator:
    """One thing to look up."""

    value: str
    kind: IndicatorClass

    @classmethod
    def parse(cls, value: str) -> Indicator:
        return cls(value=value.strip(), kind=classify(value))

    @property
    def key(self) -> str:
        """The cache key.

        Case folded for the classes where case carries no meaning, which is
        every class here except a URL path. A hash written in upper case and
        the same hash in lower case are one indicator and must not be two cache
        entries, each spending its own quota.
        """
        if self.kind is IndicatorClass.URL:
            return f"{self.kind.value}:{self.value}"
        return f"{self.kind.value}:{self.value.lower()}"


@dataclass(frozen=True)
class ProviderVerdict:
    """One provider's answer about one indicator."""

    provider: str
    disposition: Disposition
    score: float | None = None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Enrichment:
    """The answer a caller gets back."""

    indicator: Indicator
    disposition: Disposition
    verdicts: tuple[ProviderVerdict, ...] = ()
    source: Source = Source.PROVIDER
    fetched_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    # Set when the answer came from a hedged request, so the benchmark can
    # count what hedging actually bought.
    hedged: bool = False
    error: str | None = None

    @property
    def cacheable(self) -> bool:
        """Whether this answer is a fact about the indicator.

        An error is a fact about the network or the provider. Caching it would
        pin a transient failure to an indicator for the length of a TTL, and
        the indicator would then look clean for as long as the entry lived.
        """
        return self.disposition is not Disposition.ERROR
