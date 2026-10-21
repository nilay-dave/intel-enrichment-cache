"""VirusTotal v3.

The URL endpoint is the one with a trap in it. VirusTotal identifies a URL by
its base64 of the URL with the padding stripped, and sending a padded or
percent encoded identifier gets a 404 that reads exactly like "nobody has heard
of this URL". A 404 that means "you built the identifier wrong" and a 404 that
means "no data" are the same status code, so the encoding is done here once
rather than left to a caller to get wrong quietly.
"""

from __future__ import annotations

import base64
from typing import Any

import httpx

from iec.models import Disposition, Indicator, IndicatorClass, ProviderVerdict
from iec.providers.base import (
    DEFAULT_THRESHOLDS,
    ProviderError,
    RateLimited,
    Thresholds,
    disposition_from_engine_counts,
    retry_after_of,
)

BASE_URL = "https://www.virustotal.com/api/v3"

PATHS = {
    IndicatorClass.IP_ADDRESS: "ip_addresses",
    IndicatorClass.FILE_HASH: "files",
    IndicatorClass.DOMAIN: "domains",
    IndicatorClass.URL: "urls",
}


def url_identifier(value: str) -> str:
    """VirusTotal's identifier for a URL: unpadded base64 of the URL."""
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")


class VirusTotal:
    """Reads verdicts from VirusTotal. Never submits anything.

    Deliberately read only. A library whose job is enrichment should not be
    able to upload a sample, because an analyst calling an enrichment function
    does not expect a copy of a customer's file to leave the building.
    """

    name = "virustotal"
    supports = frozenset(PATHS)

    def __init__(
        self,
        api_key: str,
        *,
        client: httpx.AsyncClient | None = None,
        thresholds: Thresholds = DEFAULT_THRESHOLDS,
        timeout: float = 10.0,
    ) -> None:
        if not api_key:
            raise ValueError("an api key is required")
        self._key = api_key
        self._thresholds = thresholds
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=timeout)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def _path(self, indicator: Indicator) -> str:
        if indicator.kind not in PATHS:
            raise ProviderError(self.name, f"does not support {indicator.kind.value}")
        identifier = url_identifier(indicator.value) if indicator.kind is IndicatorClass.URL else indicator.value
        return f"{BASE_URL}/{PATHS[indicator.kind]}/{identifier}"

    async def lookup(self, indicator: Indicator) -> ProviderVerdict:
        try:
            response = await self._client.get(self._path(indicator), headers={"x-apikey": self._key})
        except httpx.TimeoutException as exc:
            raise ProviderError(self.name, f"timed out: {exc}") from exc
        except httpx.HTTPError as exc:
            raise ProviderError(self.name, f"request failed: {exc}") from exc

        if response.status_code == 404:
            # Their 404 for a known endpoint means no data held, which is a
            # fact about the indicator and is cacheable.
            return ProviderVerdict(self.name, Disposition.UNKNOWN, None, {"status": 404})
        if response.status_code == 429:
            raise RateLimited(
                self.name, "rate limited by the provider", status=429, retry_after=retry_after_of(response)
            )
        if response.status_code in (401, 403):
            raise ProviderError(self.name, "api key rejected", status=response.status_code)
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
        attributes = (payload.get("data") or {}).get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}
        # Defensive reads throughout. A response shape that changes should
        # degrade to unknown rather than raise a KeyError from inside an
        # enrichment, and an unknown is correct here: this client genuinely
        # does not know what the provider said.
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)
        total = malicious + suspicious + harmless + undetected

        disposition = disposition_from_engine_counts(
            malicious, suspicious, harmless, undetected, self._thresholds
        )
        return ProviderVerdict(
            provider=self.name,
            disposition=disposition,
            score=(malicious / total) if total else None,
            detail={
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "reputation": attributes.get("reputation"),
            },
        )
