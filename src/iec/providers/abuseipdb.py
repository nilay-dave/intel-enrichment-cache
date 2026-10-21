"""AbuseIPDB's check endpoint.

Addresses only, which is why ``supports`` is one class rather than a copy of
the other provider's. A client that sends a file hash here gets a 422 that
costs a request from a thousand a day allowance to learn something this
library already knew.
"""

from __future__ import annotations

from typing import Any

import httpx

from iec.models import Disposition, Indicator, IndicatorClass, ProviderVerdict
from iec.providers.base import (
    DEFAULT_THRESHOLDS,
    ProviderError,
    RateLimited,
    Thresholds,
    retry_after_of,
)

BASE_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDB:
    """Reads an address's abuse confidence. Never reports anything.

    Read only for the same reason as the other provider: an enrichment call
    should not be able to publish a customer's address as an abuser.
    """

    name = "abuseipdb"
    supports = frozenset({IndicatorClass.IP_ADDRESS})

    def __init__(
        self,
        api_key: str,
        *,
        client: httpx.AsyncClient | None = None,
        thresholds: Thresholds = DEFAULT_THRESHOLDS,
        max_age_days: int = 90,
        timeout: float = 10.0,
    ) -> None:
        if not api_key:
            raise ValueError("an api key is required")
        self._key = api_key
        self._thresholds = thresholds
        self._max_age_days = max_age_days
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=timeout)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def lookup(self, indicator: Indicator) -> ProviderVerdict:
        if indicator.kind not in self.supports:
            raise ProviderError(self.name, f"does not support {indicator.kind.value}")
        try:
            response = await self._client.get(
                BASE_URL,
                params={"ipAddress": indicator.value, "maxAgeInDays": self._max_age_days},
                headers={"Key": self._key, "Accept": "application/json"},
            )
        except httpx.TimeoutException as exc:
            raise ProviderError(self.name, f"timed out: {exc}") from exc
        except httpx.HTTPError as exc:
            raise ProviderError(self.name, f"request failed: {exc}") from exc

        if response.status_code == 429:
            raise RateLimited(
                self.name, "rate limited by the provider", status=429, retry_after=retry_after_of(response)
            )
        if response.status_code in (401, 403):
            raise ProviderError(self.name, "api key rejected", status=response.status_code)
        if response.status_code == 422:
            raise ProviderError(self.name, "address rejected as malformed", status=422)
        if response.status_code >= 500:
            raise ProviderError(self.name, f"server error {response.status_code}", status=response.status_code)
        if response.status_code != 200:
            raise ProviderError(self.name, f"unexpected status {response.status_code}", status=response.status_code)

        try:
            payload = response.json()
        except ValueError as exc:
            raise ProviderError(self.name, "response was not json") from exc
        return self._verdict(payload)

    def _verdict(self, payload: dict[str, Any]) -> ProviderVerdict:
        data = payload.get("data") or {}
        raw_score = data.get("abuseConfidenceScore")
        if raw_score is None:
            return ProviderVerdict(self.name, Disposition.UNKNOWN, None, {"reason": "no confidence score"})
        confidence = int(raw_score)
        reports = int(data.get("totalReports") or 0)

        if confidence >= self._thresholds.abuse_confidence_malicious:
            disposition = Disposition.MALICIOUS
        elif confidence >= self._thresholds.abuse_confidence_suspicious:
            disposition = Disposition.SUSPICIOUS
        elif reports == 0:
            # A zero score with nobody having reported it is nobody having
            # looked, which is a shorter lived answer than an all clear.
            disposition = Disposition.UNKNOWN
        else:
            disposition = Disposition.HARMLESS

        return ProviderVerdict(
            provider=self.name,
            disposition=disposition,
            score=confidence / 100.0,
            detail={
                "abuse_confidence_score": confidence,
                "total_reports": reports,
                "country_code": data.get("countryCode"),
                "is_whitelisted": data.get("isWhitelisted"),
            },
        )
