# sqlite3.Connection as a context manager commits or rolls back a
# transaction. It does not close the connection, which is a footgun worth
# naming because three tests in this repository used it that way and leaked a
# handle each. contextlib.closing is what closes. The library itself always
# used closing; only these tests were wrong.
import pytest

from iec.cache import DEFAULT_TTL_SECONDS, SqliteCache, TTLPolicy
from iec.models import Disposition, Enrichment, Indicator, IndicatorClass, ProviderVerdict, Source


class Clock:
    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def cache(tmp_path):
    clock = Clock()
    store = SqliteCache(tmp_path / "cache.sqlite", clock=clock)
    yield clock, store
    store.close()


def enrichment(value="8.8.8.8", disposition=Disposition.HARMLESS, verdicts=None):
    indicator = Indicator.parse(value)
    return Enrichment(
        indicator=indicator,
        disposition=disposition,
        verdicts=verdicts
        if verdicts is not None
        else (ProviderVerdict("virustotal", disposition, 0.0, {"engines": 94}),),
    )


class TestRoundTrip:
    async def test_a_miss_returns_none_and_is_counted(self, cache):
        _, store = cache
        assert await store.get("ip_address:1.1.1.1") is None
        assert store.stats.misses == 1
        assert store.stats.hits == 0

    async def test_a_stored_answer_comes_back(self, cache):
        _, store = cache
        original = enrichment()
        assert await store.put(original, 3600.0) is True
        found = await store.get(original.indicator.key)
        assert found is not None
        assert found.disposition is Disposition.HARMLESS
        assert found.indicator == original.indicator

    async def test_the_source_is_rewritten_to_cache(self, cache):
        """A caller has to be able to tell a stored answer from a fresh one,
        or every measurement of hit rate comes from somewhere else."""
        _, store = cache
        original = enrichment()
        await store.put(original, 3600.0)
        found = await store.get(original.indicator.key)
        assert found.source is Source.CACHE

    async def test_provider_verdicts_survive_the_round_trip(self, cache):
        _, store = cache
        original = enrichment(
            verdicts=(
                ProviderVerdict("virustotal", Disposition.MALICIOUS, 0.8, {"engines": 94, "detections": 71}),
                ProviderVerdict("abuseipdb", Disposition.SUSPICIOUS, 0.4, {"reports": 12}),
            )
        )
        await store.put(original, 3600.0)
        found = await store.get(original.indicator.key)
        assert [verdict.provider for verdict in found.verdicts] == ["virustotal", "abuseipdb"]
        assert found.verdicts[0].detail == {"engines": 94, "detections": 71}
        assert found.verdicts[1].score == 0.4

    async def test_storing_the_same_key_twice_replaces_the_entry(self, cache):
        _, store = cache
        await store.put(enrichment(disposition=Disposition.HARMLESS), 3600.0)
        await store.put(enrichment(disposition=Disposition.MALICIOUS), 3600.0)
        found = await store.get("ip_address:8.8.8.8")
        assert found.disposition is Disposition.MALICIOUS
        assert await store.count() == 1

    async def test_a_hash_is_cached_case_insensitively(self, cache):
        """The same hash in two cases is one indicator. Two entries would each
        spend their own quota for one answer."""
        _, store = cache
        upper = "D41D8CD98F00B204E9800998ECF8427E"
        await store.put(enrichment(value=upper), 3600.0)
        assert await store.get(Indicator.parse(upper.lower()).key) is not None


class TestExpiry:
    async def test_an_expired_entry_reads_as_a_miss(self, cache):
        clock, store = cache
        await store.put(enrichment(), 100.0)
        clock.now += 101
        assert await store.get("ip_address:8.8.8.8") is None
        assert store.stats.expired == 1
        assert store.stats.misses == 1

    async def test_an_entry_is_live_right_up_to_its_expiry(self, cache):
        clock, store = cache
        await store.put(enrichment(), 100.0)
        clock.now += 99.9
        assert await store.get("ip_address:8.8.8.8") is not None

    async def test_an_expired_entry_is_deleted_on_the_way_past(self, cache):
        """Rather than by a sweeper. The only moment anyone cares about a key
        is when it is asked for, and a background task would be a thing to own
        for no gain."""
        clock, store = cache
        await store.put(enrichment(), 100.0)
        clock.now += 101
        await store.get("ip_address:8.8.8.8")
        assert await store.count() == 0

    async def test_purge_removes_every_expired_entry(self, cache):
        clock, store = cache
        await store.put(enrichment("8.8.8.8"), 100.0)
        await store.put(enrichment("1.1.1.1"), 10_000.0)
        clock.now += 101
        assert await store.purge_expired() == 1
        assert await store.count() == 1

    async def test_a_zero_or_negative_lifetime_is_refused(self, cache):
        _, store = cache
        assert await store.put(enrichment(), 0.0) is False
        assert await store.put(enrichment(), -1.0) is False
        assert store.stats.rejected == 2


class TestErrorsAreNotFacts:
    async def test_an_error_result_is_never_stored(self, cache):
        """An error is a fact about the network, not about the indicator.
        Storing it pins a transient failure to the indicator for a whole TTL,
        and the indicator looks clean until it expires."""
        _, store = cache
        failed = Enrichment(
            indicator=Indicator.parse("8.8.8.8"), disposition=Disposition.ERROR, error="connect timeout"
        )
        assert await store.put(failed, 3600.0) is False
        assert await store.get("ip_address:8.8.8.8") is None
        assert store.stats.rejected == 1

    async def test_an_unknown_result_is_stored(self, cache):
        """Distinct from an error: the provider answered and had nothing, which
        is a fact about the indicator and is where the quota goes on a long
        tailed stream."""
        _, store = cache
        unknown = Enrichment(indicator=Indicator.parse("8.8.8.8"), disposition=Disposition.UNKNOWN)
        assert await store.put(unknown, 3600.0) is True
        assert (await store.get("ip_address:8.8.8.8")).disposition is Disposition.UNKNOWN


class TestTTLPolicy:
    def test_each_class_has_its_own_lifetime(self):
        policy = TTLPolicy()
        hours = {
            kind: policy.seconds_for(kind, Disposition.HARMLESS) / 3600 for kind in IndicatorClass
        }
        assert hours[IndicatorClass.FILE_HASH] > hours[IndicatorClass.DOMAIN]
        assert hours[IndicatorClass.DOMAIN] > hours[IndicatorClass.URL]
        assert hours[IndicatorClass.URL] > hours[IndicatorClass.IP_ADDRESS]

    def test_an_address_is_the_shortest_lived(self):
        """A stale clean verdict on an address is the most expensive wrong
        answer this library can give."""
        policy = TTLPolicy()
        shortest = min(IndicatorClass, key=lambda kind: policy.seconds_for(kind, Disposition.HARMLESS))
        assert shortest is IndicatorClass.IP_ADDRESS

    def test_an_unknown_answer_is_shorter_lived_than_a_known_one(self):
        policy = TTLPolicy()
        for kind in IndicatorClass:
            known = policy.seconds_for(kind, Disposition.MALICIOUS)
            unknown = policy.seconds_for(kind, Disposition.UNKNOWN)
            assert unknown <= known

    def test_a_uniform_policy_gives_everything_one_lifetime(self):
        """What ADR-001 compares the per class policy against."""
        policy = TTLPolicy.uniform(3600.0)
        for kind in IndicatorClass:
            assert policy.seconds_for(kind, Disposition.HARMLESS) == 3600.0
            assert policy.seconds_for(kind, Disposition.UNKNOWN) == 3600.0

    def test_an_override_replaces_only_the_class_it_names(self):
        policy = TTLPolicy(by_class={**DEFAULT_TTL_SECONDS, IndicatorClass.IP_ADDRESS: 60.0})
        assert policy.seconds_for(IndicatorClass.IP_ADDRESS, Disposition.HARMLESS) == 60.0
        assert policy.seconds_for(IndicatorClass.FILE_HASH, Disposition.HARMLESS) == 7 * 24 * 3600.0


class TestStats:
    async def test_the_hit_rate_counts_lookups_not_stores(self, cache):
        _, store = cache
        await store.put(enrichment(), 3600.0)
        await store.get("ip_address:8.8.8.8")
        await store.get("ip_address:9.9.9.9")
        assert store.stats.lookups == 2
        assert store.stats.hit_rate == 0.5

    async def test_the_hit_rate_is_zero_with_no_lookups(self, cache):
        _, store = cache
        assert store.stats.hit_rate == 0.0


class TestStorage:
    async def test_write_ahead_logging_is_on(self, cache):
        """Readers must not block the writer. Several workers against one
        volume is common enough that the default journal would make the cache
        the contention point it was added to remove."""
        import sqlite3
        from contextlib import closing

        _, store = cache
        with closing(sqlite3.connect(store._path)) as connection:
            assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"

    async def test_entries_survive_reopening_the_file(self, tmp_path):
        first = SqliteCache(tmp_path / "cache.sqlite")
        await first.put(enrichment(), 3600.0)
        first.close()
        second = SqliteCache(tmp_path / "cache.sqlite")
        assert await second.get("ip_address:8.8.8.8") is not None
        second.close()

    async def test_each_thread_gets_its_own_connection(self, cache):
        """SQLite's rule is that a connection belongs to the thread that made
        it. Thread local satisfies that by construction rather than by a
        promise, and avoids serialising reads behind one lock."""
        import asyncio

        _, store = cache
        await store.put(enrichment(), 3600.0)
        results = await asyncio.gather(*(store.get("ip_address:8.8.8.8") for _ in range(12)))
        assert all(result is not None for result in results)


class TestTeardown:
    async def test_close_releases_connections_opened_on_worker_threads(self, tmp_path):
        """The thread local alone was not enough. close() ran on the calling
        thread and released that thread's connection, leaving one open per
        worker thread in the pool. It showed up as a ResourceWarning about an
        unclosed database, which is the kind of warning that is easy to
        dismiss and was a real file handle leak.
        """
        import asyncio

        store = SqliteCache(tmp_path / "cache.sqlite")
        await store.put(enrichment(), 3600.0)
        await asyncio.gather(*(store.get("ip_address:8.8.8.8") for _ in range(16)))
        assert len(store._connections) > 1, "the thread pool should have opened several"
        store.close()
        assert store._connections == []

    async def test_a_closed_cache_raises_rather_than_reopening_silently(self, tmp_path):
        """Reopening on demand would make close() a suggestion.

        The first version of close() left the thread local empty, so the next
        lookup opened a fresh connection and the caller who thought they had
        released the file found it taken again, with the leak back and nothing
        to show it. Failing where the mistake is made is the only useful
        behaviour.
        """
        store = SqliteCache(tmp_path / "cache.sqlite")
        await store.put(enrichment(), 3600.0)
        store.close()
        with pytest.raises(RuntimeError, match="closed"):
            await store.get("ip_address:8.8.8.8")

    async def test_closing_twice_is_harmless(self, tmp_path):
        store = SqliteCache(tmp_path / "cache.sqlite")
        store.close()
        store.close()

    async def test_it_works_as_a_context_manager(self, tmp_path):
        with SqliteCache(tmp_path / "cache.sqlite") as store:
            assert await store.put(enrichment(), 3600.0) is True
        assert store._connections == []
