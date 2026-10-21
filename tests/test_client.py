"""End to end tests with the network mocked.

No API key and no outbound request anywhere in this suite. A library whose
tests need credentials is a library nobody can contribute to, and one whose
tests hit a live provider spends somebody's quota every time CI runs.
"""

import asyncio

import httpx
import pytest
import respx

from iec import (
    AbuseIPDB,
    DailyQuota,
    Disposition,
    EnrichmentClient,
    HedgePolicy,
    ProviderBudget,
    Rate,
    Source,
    SqliteCache,
    TTLPolicy,
    VirusTotal,
    preset,
)

VT_IP = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
VT_FILE = "https://www.virustotal.com/api/v3/files/{digest}"
ABUSE = "https://api.abuseipdb.com/api/v2/check"


def vt_body(malicious=0, suspicious=0, harmless=70, undetected=20, reputation=0):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                },
                "reputation": reputation,
            }
        }
    }


def abuse_body(score=0, reports=0):
    return {"data": {"abuseConfidenceScore": score, "totalReports": reports, "countryCode": "US"}}


class Clock:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def plumbing(tmp_path):
    clock = Clock()
    cache = SqliteCache(tmp_path / "cache.sqlite", clock=lambda: 1_700_000_000.0 + clock.now)
    quota = DailyQuota(tmp_path / "quota.sqlite", clock=lambda: 1_700_000_000.0 + clock.now)
    yield clock, cache, quota
    cache.close()


def build(plumbing, *, providers=("vt",), hedge=None, ttl=None, vt_rate=None, vt_daily=None):
    clock, cache, quota = plumbing
    budgets = []
    http = httpx.AsyncClient(timeout=5.0)
    if "vt" in providers:
        budgets.append(
            ProviderBudget(
                provider=VirusTotal("test-key", client=http),
                rate=vt_rate or Rate(4, 60.0),
                daily_limit=vt_daily if vt_daily is not None else 500,
            )
        )
    if "abuse" in providers:
        budgets.append(
            ProviderBudget.from_preset(AbuseIPDB("test-key", client=http), preset("abuseipdb-check-free"))
        )
    client = EnrichmentClient(
        budgets,
        cache=cache,
        quota=quota,
        ttl=ttl,
        hedge=hedge,
        clock=lambda: clock.now,
        sleep=_advance(clock),
    )
    return client, clock, http


def _advance(clock):
    async def sleep(seconds: float) -> None:
        clock.now += seconds
        await asyncio.sleep(0)

    return sleep


class TestSingleLookup:
    @respx.mock
    async def test_a_clean_address_comes_back_harmless(self, plumbing):
        respx.get(VT_IP.format(ip="8.8.8.8")).mock(return_value=httpx.Response(200, json=vt_body()))
        client, _, http = build(plumbing)
        result = await client.enrich("8.8.8.8")
        assert result.disposition is Disposition.HARMLESS
        assert result.source is Source.PROVIDER
        assert result.verdicts[0].provider == "virustotal"
        await http.aclose()

    @respx.mock
    async def test_two_detections_are_malicious_and_one_is_suspicious(self, plumbing):
        respx.get(VT_FILE.format(digest="a" * 64)).mock(return_value=httpx.Response(200, json=vt_body(malicious=2)))
        client, _, http = build(plumbing)
        assert (await client.enrich("a" * 64)).disposition is Disposition.MALICIOUS
        await http.aclose()

    @respx.mock
    async def test_a_404_is_unknown_rather_than_an_error(self, plumbing):
        """Their 404 on a known endpoint means no data held, which is a fact
        about the indicator and is cacheable."""
        respx.get(VT_IP.format(ip="8.8.8.8")).mock(return_value=httpx.Response(404))
        client, _, http = build(plumbing)
        result = await client.enrich("8.8.8.8")
        assert result.disposition is Disposition.UNKNOWN
        await http.aclose()

    @respx.mock
    async def test_an_unsupported_class_is_not_sent_to_a_provider(self, plumbing):
        """AbuseIPDB takes addresses only. Sending a hash would cost a request
        from a thousand a day to learn something the library already knew."""
        route = respx.get(ABUSE)
        client, _, http = build(plumbing, providers=("abuse",))
        result = await client.enrich("a" * 64)
        assert result.disposition is Disposition.ERROR
        assert "no provider supports file_hash" in result.error
        assert not route.called
        await http.aclose()


class TestCache:
    @respx.mock
    async def test_a_second_lookup_costs_no_request(self, plumbing):
        route = respx.get(VT_IP.format(ip="8.8.8.8")).mock(return_value=httpx.Response(200, json=vt_body()))
        client, _, http = build(plumbing)
        await client.enrich("8.8.8.8")
        second = await client.enrich("8.8.8.8")
        assert second.source is Source.CACHE
        assert route.call_count == 1
        assert client.stats.provider_requests == 1
        await http.aclose()

    @respx.mock
    async def test_an_expired_entry_is_fetched_again(self, plumbing):
        route = respx.get(VT_IP.format(ip="8.8.8.8")).mock(return_value=httpx.Response(200, json=vt_body()))
        client, clock, http = build(plumbing, ttl=TTLPolicy.uniform(100.0))
        await client.enrich("8.8.8.8")
        clock.now += 101
        assert (await client.enrich("8.8.8.8")).source is Source.PROVIDER
        assert route.call_count == 2
        await http.aclose()

    @respx.mock
    async def test_an_error_is_not_cached(self, plumbing):
        """Otherwise a transient failure pins itself to the indicator for a
        whole lifetime, during which the indicator reads as unresolved."""
        route = respx.get(VT_IP.format(ip="8.8.8.8")).mock(return_value=httpx.Response(500))
        client, _, http = build(plumbing)
        first = await client.enrich("8.8.8.8")
        assert first.disposition is Disposition.ERROR
        await client.enrich("8.8.8.8")
        assert route.call_count == 2
        await http.aclose()

    @respx.mock
    async def test_a_file_hash_outlives_an_address_in_the_cache(self, plumbing):
        respx.get(VT_IP.format(ip="8.8.8.8")).mock(return_value=httpx.Response(200, json=vt_body()))
        respx.get(VT_FILE.format(digest="b" * 64)).mock(return_value=httpx.Response(200, json=vt_body()))
        client, clock, http = build(plumbing)
        await client.enrich("8.8.8.8")
        await client.enrich("b" * 64)
        clock.now += 5 * 3600  # past the address lifetime, inside the hash one
        assert (await client.enrich("b" * 64)).source is Source.CACHE
        assert (await client.enrich("8.8.8.8")).source is Source.PROVIDER
        await http.aclose()


class TestCoalescing:
    @respx.mock
    async def test_a_burst_of_one_indicator_costs_one_request(self, plumbing):
        """Where the quota saving on a bursty stream actually comes from."""
        route = respx.get(VT_IP.format(ip="8.8.8.8")).mock(return_value=httpx.Response(200, json=vt_body()))
        client, _, http = build(plumbing)
        results = await client.enrich_many(["8.8.8.8"] * 25, concurrency=25)
        assert route.call_count == 1
        assert client.stats.provider_requests == 1
        assert sum(1 for result in results if result.source is Source.COALESCED) == 24
        await http.aclose()

    @respx.mock
    async def test_a_coalesced_answer_is_not_counted_as_a_cache_hit(self, plumbing):
        """Counting it as one would overstate what the cache achieves, and on a
        bursty stream the two are not the same size."""
        respx.get(VT_IP.format(ip="8.8.8.8")).mock(return_value=httpx.Response(200, json=vt_body()))
        client, _, http = build(plumbing)
        await client.enrich_many(["8.8.8.8"] * 10, concurrency=10)
        assert client.stats.coalesced == 9
        assert client.stats.from_cache == 0
        assert client.stats.avoided_rate == 0.9
        await http.aclose()


class TestQuota:
    @respx.mock
    async def test_an_exhausted_allowance_refuses_before_any_request(self, plumbing):
        route = respx.get(VT_IP.format(ip="1.1.1.1")).mock(return_value=httpx.Response(200, json=vt_body()))
        client, _, http = build(plumbing, vt_daily=2, vt_rate=Rate(100, 60.0))
        for address in ("1.1.1.1", "1.1.1.2", "1.1.1.3"):
            respx.get(VT_IP.format(ip=address)).mock(return_value=httpx.Response(200, json=vt_body()))
            await client.enrich(address)
        assert client.stats.quota_refused == 1
        assert client.stats.provider_requests == 2
        await http.aclose()
        assert route.call_count == 1

    @respx.mock
    async def test_remaining_reports_what_is_left(self, plumbing):
        respx.get(VT_IP.format(ip="8.8.8.8")).mock(return_value=httpx.Response(200, json=vt_body()))
        client, _, http = build(plumbing, vt_daily=10)
        await client.enrich("8.8.8.8")
        assert client.remaining() == {"virustotal": 9}
        await http.aclose()

    @respx.mock
    async def test_a_provider_429_is_counted_apart_from_an_error(self, plumbing):
        """Reaching a 429 means the local limiter was wrong, which calls for
        fixing the preset rather than retrying."""
        respx.get(VT_IP.format(ip="8.8.8.8")).mock(
            return_value=httpx.Response(429, headers={"Retry-After": "30"})
        )
        client, _, http = build(plumbing)
        result = await client.enrich("8.8.8.8")
        assert result.disposition is Disposition.ERROR
        assert client.stats.provider_rate_limited == 1
        assert client.stats.provider_errors == 0
        await http.aclose()


class TestPacing:
    @respx.mock
    async def test_requests_are_paced_to_the_short_window_rate(self, plumbing):
        for index in range(6):
            respx.get(VT_IP.format(ip=f"10.0.0.{index}")).mock(
                return_value=httpx.Response(200, json=vt_body())
            )
        client, clock, http = build(plumbing, vt_rate=Rate(4, 60.0))
        for index in range(6):
            await client.enrich(f"10.0.0.{index}")
        # Four free, then one every fifteen seconds.
        assert clock.now == pytest.approx(30.0)
        await http.aclose()


class TestSeveralProviders:
    @respx.mock
    async def test_the_worst_verdict_wins(self, plumbing):
        """One provider calling an address malicious while another has never
        heard of it is not a tie, and averaging a verdict with an absence of
        one produces a number that means nothing."""
        respx.get(VT_IP.format(ip="8.8.8.8")).mock(return_value=httpx.Response(200, json=vt_body()))
        respx.get(ABUSE).mock(return_value=httpx.Response(200, json=abuse_body(score=90, reports=40)))
        client, _, http = build(plumbing, providers=("vt", "abuse"))
        result = await client.enrich("8.8.8.8")
        assert result.disposition is Disposition.MALICIOUS
        assert len(result.verdicts) == 2
        await http.aclose()

    @respx.mock
    async def test_a_partial_answer_beats_an_error(self, plumbing):
        """An analyst with one verdict and a note about the other source is
        better served than one with an exception, and discarding good data
        throws away quota already spent."""
        respx.get(VT_IP.format(ip="8.8.8.8")).mock(return_value=httpx.Response(200, json=vt_body(malicious=5)))
        respx.get(ABUSE).mock(return_value=httpx.Response(500))
        client, _, http = build(plumbing, providers=("vt", "abuse"))
        result = await client.enrich("8.8.8.8")
        assert result.disposition is Disposition.MALICIOUS
        assert len(result.verdicts) == 1
        assert "abuseipdb" in result.error
        await http.aclose()

    @respx.mock
    async def test_every_provider_failing_is_an_error(self, plumbing):
        respx.get(VT_IP.format(ip="8.8.8.8")).mock(return_value=httpx.Response(500))
        respx.get(ABUSE).mock(return_value=httpx.Response(503))
        client, _, http = build(plumbing, providers=("vt", "abuse"))
        result = await client.enrich("8.8.8.8")
        assert result.disposition is Disposition.ERROR
        assert client.stats.provider_errors == 2
        await http.aclose()


class TestHedging:
    @respx.mock
    async def test_hedging_off_sends_one_request(self, plumbing):
        route = respx.get(VT_IP.format(ip="8.8.8.8")).mock(return_value=httpx.Response(200, json=vt_body()))
        client, _, http = build(plumbing, hedge=HedgePolicy(enabled=False))
        await client.enrich("8.8.8.8")
        assert route.call_count == 1
        assert client.stats.hedges_sent == 0
        await http.aclose()

    @respx.mock
    async def test_a_hedge_is_counted_as_a_request_it_spent(self, plumbing):
        """The point of the whole exercise: a hedge is quota, and a latency
        improvement reported without it is reported without its cost."""
        calls = {"n": 0}

        async def responder(request):
            calls["n"] += 1
            if calls["n"] == 1:
                await asyncio.sleep(0.2)
            return httpx.Response(200, json=vt_body())

        respx.get(VT_IP.format(ip="8.8.8.8")).mock(side_effect=responder)
        client, _, http = build(
            plumbing, hedge=HedgePolicy(enabled=True, after_seconds=0.01, min_remaining_fraction=0.0)
        )
        result = await client.enrich("8.8.8.8")
        assert result.disposition is Disposition.HARMLESS
        assert calls["n"] == 2
        assert client.stats.hedges_sent == 1
        assert client.stats.provider_requests == 2
        await http.aclose()


class TestStats:
    @respx.mock
    async def test_requests_per_thousand_is_the_headline_number(self, plumbing):
        respx.get(VT_IP.format(ip="8.8.8.8")).mock(return_value=httpx.Response(200, json=vt_body()))
        client, _, http = build(plumbing)
        for _ in range(10):
            await client.enrich("8.8.8.8")
        assert client.stats.requested == 10
        assert client.stats.provider_requests == 1
        assert client.stats.requests_per_thousand() == 100.0
        assert client.stats.cache_hit_rate == 0.9
        await http.aclose()

    def test_percentiles_on_an_empty_sample_are_zero(self):
        from iec.client import ClientStats

        assert ClientStats().percentile(0.99) == 0.0

    def test_the_percentile_definition_is_nearest_rank(self):
        """Stated because three definitions disagree by a whole index at small
        sample sizes, and a p99 is read as though it were exact."""
        from iec.client import ClientStats

        stats = ClientStats(latencies_ms=[float(value) for value in range(1, 101)])
        assert stats.percentile(0.5) == 50.0
        assert stats.percentile(0.95) == 95.0
        assert stats.percentile(0.99) == 99.0
        assert stats.percentile(1.0) == 100.0
        assert stats.percentile(0.0) == 1.0

    def test_a_percentile_never_interpolates(self):
        """Every number it reports is a latency that was observed, not an
        average of two that were not."""
        from iec.client import ClientStats

        stats = ClientStats(latencies_ms=[10.0, 20.0, 90.0])
        assert stats.percentile(0.5) in {10.0, 20.0, 90.0}
        assert stats.percentile(0.99) == 90.0


def test_a_client_with_no_providers_is_refused(tmp_path):
    with pytest.raises(ValueError, match="at least one provider"):
        EnrichmentClient([], cache=SqliteCache(tmp_path / "c.sqlite"), quota=tmp_path / "q.sqlite")
