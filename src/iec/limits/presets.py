"""Named rate limit presets, each carrying where its numbers came from.

A library that hardcodes a provider's limits is wrong the moment the provider
changes a tier, and it was never right for the user whose account is on a
different one. The limits here are therefore configuration with defaults, not
facts the library asserts.

Each preset carries a ``source`` naming the documentation the figures were read
from and ``checked_on`` saying when. That is not decoration: a reader who wants
to know whether the preset is still true needs to know where to look, and a
figure in a library with no provenance is a figure nobody can audit. The numbers
below were read from the vendors' own documentation on the date recorded, not
from memory, and the docstring of each one says what it covers.

``verify_against_your_account`` is True on every preset here because none of
them can be checked from inside this library. A caller on a paid tier must pass
their own Rate; a caller on a free tier should confirm the preset still matches
what their dashboard says. The client reconciles against response headers where
a provider sends them, which is the only source of truth that belongs to the
caller rather than to this file.
"""

from __future__ import annotations

from dataclasses import dataclass

from iec.limits.bucket import Rate


@dataclass(frozen=True)
class Preset:
    """A provider tier's documented limits, with provenance."""

    name: str
    rate: Rate
    daily_limit: int | None
    daily_window_seconds: float
    source: str
    checked_on: str
    note: str = ""
    verify_against_your_account: bool = True

    def describe(self) -> str:
        parts = [f"{self.rate.allowance} per {self.rate.per_seconds:.0f}s"]
        if self.daily_limit is not None:
            parts.append(f"{self.daily_limit} per {self.daily_window_seconds / 3600:.0f}h")
        return f"{self.name}: {', '.join(parts)} (read from {self.source} on {self.checked_on})"


# VirusTotal public API. Their documentation states the public API is limited
# to 500 requests per day and a rate of 4 requests per minute.
VIRUSTOTAL_PUBLIC = Preset(
    name="virustotal-public",
    rate=Rate(allowance=4, per_seconds=60.0),
    daily_limit=500,
    daily_window_seconds=86_400.0,
    source="docs.virustotal.com, public versus premium API",
    checked_on="2026-10-21",
    note=(
        "The documented day is not defined as calendar or rolling, so this library counts a rolling "
        "24 hours. Under counting against a calendar reset is harmless; over counting against a rolling "
        "window is how an account is suspended."
    ),
)

# AbuseIPDB standard (free) plan. Their documentation lists the daily limit per
# endpoint rather than per account, and the two endpoints differ, which is why
# this is split rather than given one number.
ABUSEIPDB_CHECK_FREE = Preset(
    name="abuseipdb-check-free",
    rate=Rate(allowance=10, per_seconds=60.0),
    daily_limit=1_000,
    daily_window_seconds=86_400.0,
    source="docs.abuseipdb.com, rate limits, CHECK endpoint on the standard plan",
    checked_on="2026-10-21",
    note=(
        "The daily figure of 1,000 is documented. The per minute figure is not: AbuseIPDB publishes a "
        "daily limit for this endpoint and no short window one, so 10 per minute is this library's own "
        "conservative pacing choice and is labelled as such rather than presented as their number. "
        "Raise it if your own testing shows the endpoint tolerates more."
    ),
)

ABUSEIPDB_REPORTS_FREE = Preset(
    name="abuseipdb-reports-free",
    rate=Rate(allowance=5, per_seconds=60.0),
    daily_limit=100,
    daily_window_seconds=86_400.0,
    source="docs.abuseipdb.com, rate limits, REPORTS endpoint on the standard plan",
    checked_on="2026-10-21",
    note=(
        "100 a day is documented; the per minute figure is this library's pacing choice, as above. "
        "A tenth of the CHECK allowance, so a client that treats the two endpoints as one budget will "
        "exhaust this one first without noticing."
    ),
)

PRESETS: dict[str, Preset] = {
    preset.name: preset
    for preset in (VIRUSTOTAL_PUBLIC, ABUSEIPDB_CHECK_FREE, ABUSEIPDB_REPORTS_FREE)
}


def preset(name: str) -> Preset:
    """Look up a preset by name, listing the alternatives if it is absent."""
    try:
        return PRESETS[name]
    except KeyError:
        available = ", ".join(sorted(PRESETS))
        raise KeyError(f"no preset called {name!r}; available: {available}") from None
