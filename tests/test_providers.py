"""Provider level tests: every status code and every malformed body.

The error paths are the ones that matter here. A provider client is exercised
on its happy path constantly and on its 403 path once, at 03:00, by somebody
who has just rotated a key.
"""

import httpx
import pytest
import respx

from iec.models import Disposition, Indicator, IndicatorClass
from iec.providers import (
    AbuseIPDB,
    ProviderError,
    RateLimited,
    Thresholds,
    VirusTotal,
    disposition_from_engine_counts,
    url_identifier,
)
from iec.providers.base import retry_after_of

VT = "https://www.virustotal.com/api/v3"
ABUSE = "https://api.abuseipdb.com/api/v2/check"


def vt_body(malicious=0, suspicious=0, harmless=70, undetected=20):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                },
                "reputation": 3,
            }
        }
    }


class TestConstruction:
    @pytest.mark.parametrize("factory", [VirusTotal, AbuseIPDB])
    def test_an_empty_api_key_is_refused_up_front(self, factory):
        """Rather than at the first 401, which costs a request to discover."""
        with pytest.raises(ValueError, match="api key"):
            factory("")

    def test_each_provider_declares_what_it_can_answer(self):
        assert VirusTotal.supports == frozenset(IndicatorClass)
        assert AbuseIPDB.supports == {IndicatorClass.IP_ADDRESS}


class TestUrlIdentifier:
    def test_the_padding_is_stripped(self):
        """A padded identifier returns a 404 that reads exactly like no data
        held, so the two failures are indistinguishable to a caller."""
        for value in ("https://a.test", "https://a.test/x", "https://a.test/xy"):
            assert "=" not in url_identifier(value)

    def test_it_is_url_safe_base64(self):
        import base64

        value = "https://a.test/path?q=1&r=2"
        assert base64.urlsafe_b64decode(url_identifier(value) + "==").decode().startswith("https://a.test")

    def test_two_urls_differing_only_in_path_get_different_identifiers(self):
        assert url_identifier("https://a.test/one") != url_identifier("https://a.test/two")


class TestThresholds:
    @pytest.mark.parametrize(
        ("malicious", "suspicious", "expected"),
        [
            (0, 0, Disposition.HARMLESS),
            (1, 0, Disposition.SUSPICIOUS),
            (2, 0, Disposition.MALICIOUS),
            (9, 0, Disposition.MALICIOUS),
            (0, 1, Disposition.SUSPICIOUS),
        ],
    )
    def test_the_default_line_between_dispositions(self, malicious, suspicious, expected):
        assert disposition_from_engine_counts(malicious, suspicious, 70, 20) is expected

    def test_all_zeroes_is_unknown_not_harmless(self):
        """Nobody having looked is not everybody having cleared it, and the two
        deserve different cache lifetimes."""
        assert disposition_from_engine_counts(0, 0, 0, 0) is Disposition.UNKNOWN

    def test_the_line_is_configurable(self):
        strict = Thresholds(malicious_engines=1)
        assert disposition_from_engine_counts(1, 0, 70, 20, strict) is Disposition.MALICIOUS
        lenient = Thresholds(malicious_engines=5, suspicious_engines=3)
        assert disposition_from_engine_counts(2, 0, 70, 20, lenient) is Disposition.HARMLESS


class TestRetryAfter:
    def test_a_delay_in_seconds_is_read(self):
        assert retry_after_of(httpx.Response(429, headers={"Retry-After": "30"})) == 30.0

    def test_an_absent_header_is_none(self):
        assert retry_after_of(httpx.Response(429)) is None

    def test_an_http_date_is_ignored_rather_than_parsed(self):
        """A date parsed into a number can be wrong by a clock skew, and the
        caller has its own backoff to fall back on."""
        assert retry_after_of(httpx.Response(429, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"})) is None

    def test_a_negative_delay_is_ignored(self):
        assert retry_after_of(httpx.Response(429, headers={"Retry-After": "-5"})) is None


class TestVirusTotal:
    @respx.mock
    async def test_a_lookup_sends_the_api_key_in_the_header(self):
        route = respx.get(f"{VT}/ip_addresses/8.8.8.8").mock(return_value=httpx.Response(200, json=vt_body()))
        provider = VirusTotal("secret-key")
        await provider.lookup(Indicator.parse("8.8.8.8"))
        assert route.calls[0].request.headers["x-apikey"] == "secret-key"
        await provider.aclose()

    @respx.mock
    @pytest.mark.parametrize(
        ("value", "path"),
        [
            ("8.8.8.8", "ip_addresses/8.8.8.8"),
            ("a" * 64, f"files/{'a' * 64}"),
            ("evil.test", "domains/evil.test"),
        ],
    )
    async def test_each_class_goes_to_its_own_endpoint(self, value, path):
        route = respx.get(f"{VT}/{path}").mock(return_value=httpx.Response(200, json=vt_body()))
        provider = VirusTotal("k")
        await provider.lookup(Indicator.parse(value))
        assert route.called
        await provider.aclose()

    @respx.mock
    async def test_a_url_goes_to_its_encoded_identifier(self):
        value = "https://evil.test/dropper"
        route = respx.get(f"{VT}/urls/{url_identifier(value)}").mock(
            return_value=httpx.Response(200, json=vt_body(malicious=4))
        )
        provider = VirusTotal("k")
        verdict = await provider.lookup(Indicator.parse(value))
        assert route.called
        assert verdict.disposition is Disposition.MALICIOUS
        await provider.aclose()

    @respx.mock
    async def test_the_score_is_the_detected_share(self):
        respx.get(f"{VT}/ip_addresses/8.8.8.8").mock(
            return_value=httpx.Response(200, json=vt_body(malicious=5, harmless=70, undetected=25))
        )
        provider = VirusTotal("k")
        verdict = await provider.lookup(Indicator.parse("8.8.8.8"))
        assert verdict.score == pytest.approx(5 / 100)
        assert verdict.detail["malicious"] == 5
        await provider.aclose()

    @respx.mock
    async def test_a_404_is_unknown_and_carries_the_status(self):
        respx.get(f"{VT}/ip_addresses/8.8.8.8").mock(return_value=httpx.Response(404))
        provider = VirusTotal("k")
        verdict = await provider.lookup(Indicator.parse("8.8.8.8"))
        assert verdict.disposition is Disposition.UNKNOWN
        assert verdict.detail["status"] == 404
        await provider.aclose()

    @respx.mock
    async def test_a_429_raises_rate_limited_with_the_retry_hint(self):
        respx.get(f"{VT}/ip_addresses/8.8.8.8").mock(return_value=httpx.Response(429, headers={"Retry-After": "45"}))
        provider = VirusTotal("k")
        with pytest.raises(RateLimited) as caught:
            await provider.lookup(Indicator.parse("8.8.8.8"))
        assert caught.value.retry_after == 45.0
        assert caught.value.status == 429
        await provider.aclose()

    @respx.mock
    @pytest.mark.parametrize("status", [401, 403])
    async def test_a_rejected_key_says_so(self, status):
        respx.get(f"{VT}/ip_addresses/8.8.8.8").mock(return_value=httpx.Response(status))
        provider = VirusTotal("k")
        with pytest.raises(ProviderError, match="api key rejected"):
            await provider.lookup(Indicator.parse("8.8.8.8"))
        await provider.aclose()

    @respx.mock
    @pytest.mark.parametrize("status", [500, 502, 503])
    async def test_a_server_error_says_so(self, status):
        respx.get(f"{VT}/ip_addresses/8.8.8.8").mock(return_value=httpx.Response(status))
        provider = VirusTotal("k")
        with pytest.raises(ProviderError, match="server error"):
            await provider.lookup(Indicator.parse("8.8.8.8"))
        await provider.aclose()

    @respx.mock
    async def test_an_unexpected_status_is_reported_with_its_code(self):
        respx.get(f"{VT}/ip_addresses/8.8.8.8").mock(return_value=httpx.Response(418))
        provider = VirusTotal("k")
        with pytest.raises(ProviderError, match="unexpected status 418"):
            await provider.lookup(Indicator.parse("8.8.8.8"))
        await provider.aclose()

    @respx.mock
    async def test_a_body_that_is_not_json_is_reported(self):
        respx.get(f"{VT}/ip_addresses/8.8.8.8").mock(return_value=httpx.Response(200, text="<html>maintenance</html>"))
        provider = VirusTotal("k")
        with pytest.raises(ProviderError, match="not json"):
            await provider.lookup(Indicator.parse("8.8.8.8"))
        await provider.aclose()

    @respx.mock
    async def test_a_response_missing_the_stats_degrades_to_unknown(self):
        """A shape change should not raise a KeyError from the middle of an
        enrichment, and unknown is honest: the client does not know what the
        provider said."""
        respx.get(f"{VT}/ip_addresses/8.8.8.8").mock(return_value=httpx.Response(200, json={"data": {}}))
        provider = VirusTotal("k")
        verdict = await provider.lookup(Indicator.parse("8.8.8.8"))
        assert verdict.disposition is Disposition.UNKNOWN
        assert verdict.score is None
        await provider.aclose()

    @respx.mock
    async def test_a_timeout_is_a_provider_error(self):
        respx.get(f"{VT}/ip_addresses/8.8.8.8").mock(side_effect=httpx.ConnectTimeout("too slow"))
        provider = VirusTotal("k")
        with pytest.raises(ProviderError, match="timed out"):
            await provider.lookup(Indicator.parse("8.8.8.8"))
        await provider.aclose()

    @respx.mock
    async def test_a_transport_failure_is_a_provider_error(self):
        respx.get(f"{VT}/ip_addresses/8.8.8.8").mock(side_effect=httpx.ConnectError("no route"))
        provider = VirusTotal("k")
        with pytest.raises(ProviderError, match="request failed"):
            await provider.lookup(Indicator.parse("8.8.8.8"))
        await provider.aclose()

    async def test_an_injected_client_is_not_closed_by_the_provider(self):
        """A caller sharing one connection pool across providers would
        otherwise have it closed underneath the others."""
        shared = httpx.AsyncClient()
        provider = VirusTotal("k", client=shared)
        await provider.aclose()
        assert not shared.is_closed
        await shared.aclose()


class TestAbuseIPDB:
    @respx.mock
    async def test_a_lookup_sends_the_key_and_the_age_window(self):
        route = respx.get(ABUSE).mock(return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 0}}))
        provider = AbuseIPDB("secret-key", max_age_days=30)
        await provider.lookup(Indicator.parse("8.8.8.8"))
        request = route.calls[0].request
        assert request.headers["Key"] == "secret-key"
        assert "maxAgeInDays=30" in str(request.url)
        await provider.aclose()

    @respx.mock
    @pytest.mark.parametrize(
        ("score", "reports", "expected"),
        [
            (100, 500, Disposition.MALICIOUS),
            (75, 10, Disposition.MALICIOUS),
            (74, 10, Disposition.SUSPICIOUS),
            (25, 3, Disposition.SUSPICIOUS),
            (24, 3, Disposition.HARMLESS),
            (0, 1, Disposition.HARMLESS),
            (0, 0, Disposition.UNKNOWN),
        ],
    )
    async def test_the_confidence_score_maps_to_a_disposition(self, score, reports, expected):
        respx.get(ABUSE).mock(
            return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": score, "totalReports": reports}})
        )
        provider = AbuseIPDB("k")
        verdict = await provider.lookup(Indicator.parse("8.8.8.8"))
        assert verdict.disposition is expected
        assert verdict.score == pytest.approx(score / 100)
        await provider.aclose()

    @respx.mock
    async def test_a_zero_score_with_no_reports_is_unknown(self):
        """Nobody has looked, which is a shorter lived answer than an all
        clear."""
        respx.get(ABUSE).mock(
            return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 0, "totalReports": 0}})
        )
        provider = AbuseIPDB("k")
        assert (await provider.lookup(Indicator.parse("8.8.8.8"))).disposition is Disposition.UNKNOWN
        await provider.aclose()

    async def test_a_hash_is_refused_without_a_request(self):
        """Sending one would cost a request from a thousand a day to learn
        something the library already knew."""
        provider = AbuseIPDB("k")
        with pytest.raises(ProviderError, match="does not support file_hash"):
            await provider.lookup(Indicator.parse("a" * 64))
        await provider.aclose()

    @respx.mock
    async def test_a_422_says_the_address_was_rejected(self):
        respx.get(ABUSE).mock(return_value=httpx.Response(422))
        provider = AbuseIPDB("k")
        with pytest.raises(ProviderError, match="malformed"):
            await provider.lookup(Indicator.parse("8.8.8.8"))
        await provider.aclose()

    @respx.mock
    async def test_a_429_raises_rate_limited(self):
        respx.get(ABUSE).mock(return_value=httpx.Response(429, headers={"Retry-After": "60"}))
        provider = AbuseIPDB("k")
        with pytest.raises(RateLimited) as caught:
            await provider.lookup(Indicator.parse("8.8.8.8"))
        assert caught.value.retry_after == 60.0
        await provider.aclose()

    @respx.mock
    @pytest.mark.parametrize("status", [401, 403])
    async def test_a_rejected_key_says_so(self, status):
        respx.get(ABUSE).mock(return_value=httpx.Response(status))
        provider = AbuseIPDB("k")
        with pytest.raises(ProviderError, match="api key rejected"):
            await provider.lookup(Indicator.parse("8.8.8.8"))
        await provider.aclose()

    @respx.mock
    async def test_a_server_error_says_so(self):
        respx.get(ABUSE).mock(return_value=httpx.Response(503))
        provider = AbuseIPDB("k")
        with pytest.raises(ProviderError, match="server error"):
            await provider.lookup(Indicator.parse("8.8.8.8"))
        await provider.aclose()

    @respx.mock
    async def test_an_unexpected_status_is_reported(self):
        respx.get(ABUSE).mock(return_value=httpx.Response(302))
        provider = AbuseIPDB("k")
        with pytest.raises(ProviderError, match="unexpected status 302"):
            await provider.lookup(Indicator.parse("8.8.8.8"))
        await provider.aclose()

    @respx.mock
    async def test_a_body_that_is_not_json_is_reported(self):
        respx.get(ABUSE).mock(return_value=httpx.Response(200, text="not json"))
        provider = AbuseIPDB("k")
        with pytest.raises(ProviderError, match="not json"):
            await provider.lookup(Indicator.parse("8.8.8.8"))
        await provider.aclose()

    @respx.mock
    async def test_a_body_with_no_score_degrades_to_unknown(self):
        respx.get(ABUSE).mock(return_value=httpx.Response(200, json={"data": {}}))
        provider = AbuseIPDB("k")
        verdict = await provider.lookup(Indicator.parse("8.8.8.8"))
        assert verdict.disposition is Disposition.UNKNOWN
        await provider.aclose()

    @respx.mock
    async def test_a_timeout_is_a_provider_error(self):
        respx.get(ABUSE).mock(side_effect=httpx.ReadTimeout("slow"))
        provider = AbuseIPDB("k")
        with pytest.raises(ProviderError, match="timed out"):
            await provider.lookup(Indicator.parse("8.8.8.8"))
        await provider.aclose()

    @respx.mock
    async def test_a_transport_failure_is_a_provider_error(self):
        respx.get(ABUSE).mock(side_effect=httpx.ConnectError("refused"))
        provider = AbuseIPDB("k")
        with pytest.raises(ProviderError, match="request failed"):
            await provider.lookup(Indicator.parse("8.8.8.8"))
        await provider.aclose()
