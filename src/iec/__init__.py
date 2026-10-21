"""Rate limit aware threat intel enrichment with caching and coalescing."""

from iec.cache import SqliteCache, TTLPolicy
from iec.client import ClientStats, EnrichmentClient, ProviderBudget
from iec.hedging import HedgePolicy
from iec.limits.bucket import Rate, TokenBucket
from iec.limits.presets import PRESETS, Preset, preset
from iec.limits.quota import DailyQuota, QuotaExhausted
from iec.models import (
    Disposition,
    Enrichment,
    Indicator,
    IndicatorClass,
    ProviderVerdict,
    Source,
    classify,
)
from iec.providers import AbuseIPDB, Provider, ProviderError, RateLimited, Thresholds, VirusTotal

__version__ = "0.1.0"

__all__ = [
    "PRESETS",
    "AbuseIPDB",
    "ClientStats",
    "DailyQuota",
    "Disposition",
    "EnrichmentClient",
    "Enrichment",
    "HedgePolicy",
    "Indicator",
    "IndicatorClass",
    "Preset",
    "Provider",
    "ProviderBudget",
    "ProviderError",
    "ProviderVerdict",
    "QuotaExhausted",
    "Rate",
    "RateLimited",
    "Source",
    "SqliteCache",
    "TTLPolicy",
    "Thresholds",
    "TokenBucket",
    "VirusTotal",
    "classify",
    "preset",
]
