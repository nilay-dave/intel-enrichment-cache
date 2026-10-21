"""What a provider has to do, and how its answer becomes a disposition.

The disposition thresholds are a judgement and are configurable. One engine out
of ninety flagging a file is usually a heuristic firing, not a verdict, and a
client that treats it as malicious will bury an analyst. Two independent
engines is a weaker claim than a sandbox detonation and a stronger one than a
single heuristic, so it maps to suspicious rather than either extreme. Those
are defaults to argue with, not findings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import httpx

from iec.models import Disposition, Indicator, IndicatorClass, ProviderVerdict


class ProviderError(Exception):
    """A provider could not be asked, or answered with something unusable."""

    def __init__(self, provider: str, message: str, *, status: int | None = None, retry_after: float | None = None):
        super().__init__(f"{provider}: {message}")
        self.provider = provider
        self.status = status
        # Taken from the response where the provider sends one. A client that
        # ignores Retry-After and backs off on its own schedule is guessing at
        # a number the provider has already told it.
        self.retry_after = retry_after


class RateLimited(ProviderError):
    """The provider refused because of its own accounting, not ours.

    Reaching this means the local limiter is wrong: too generous a preset, a
    tier that does not match, or quota spent by something else sharing the key.
    It is a distinct type so a caller can tell "we are pacing badly" apart from
    "the provider is down", which call for opposite responses.
    """


@dataclass(frozen=True)
class Thresholds:
    """Where the line between dispositions falls.

    Defaults: two or more engines calling something malicious is malicious; one
    is suspicious, because a lone detection is more often a heuristic than a
    verdict; anything a provider marks suspicious is suspicious. A response
    where every count is zero is unknown rather than harmless, since nobody
    having looked is not the same as everybody having cleared it.
    """

    malicious_engines: int = 2
    suspicious_engines: int = 1
    # AbuseIPDB returns a 0 to 100 confidence rather than engine counts.
    abuse_confidence_malicious: int = 75
    abuse_confidence_suspicious: int = 25


DEFAULT_THRESHOLDS = Thresholds()


def disposition_from_engine_counts(
    malicious: int, suspicious: int, harmless: int, undetected: int, thresholds: Thresholds = DEFAULT_THRESHOLDS
) -> Disposition:
    """Collapse a provider's engine tally into one disposition."""
    if malicious >= thresholds.malicious_engines:
        return Disposition.MALICIOUS
    if malicious >= thresholds.suspicious_engines or suspicious > 0:
        return Disposition.SUSPICIOUS
    if harmless + undetected > 0:
        return Disposition.HARMLESS
    # Nobody looked. Not the same as everybody clearing it, and the difference
    # decides whether this gets a short cache lifetime or a long one.
    return Disposition.UNKNOWN


def retry_after_of(response: httpx.Response) -> float | None:
    """The Retry-After header in seconds, if the provider sent a usable one.

    RFC 9110 allows either a delay in seconds or an HTTP date. Only the delay
    form is read here; a date is ignored rather than parsed into a number that
    might be wrong by a clock skew, and the caller falls back to its own
    backoff.
    """
    raw = response.headers.get("retry-after")
    if raw is None:
        return None
    try:
        seconds = float(raw.strip())
    except ValueError:
        return None
    return seconds if seconds >= 0 else None


class Provider(Protocol):
    """One threat intelligence source."""

    name: str
    supports: frozenset[IndicatorClass]

    async def lookup(self, indicator: Indicator) -> ProviderVerdict:
        """Ask about one indicator.

        Raises ProviderError or RateLimited. Returning an error disposition
        instead would let a transient failure be cached as a fact about the
        indicator, so the failure has to travel as an exception.
        """
        ...
