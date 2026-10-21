import pytest

from iec.models import Disposition, Enrichment, Indicator, IndicatorClass, classify


class TestClassify:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("8.8.8.8", IndicatorClass.IP_ADDRESS),
            ("0.0.0.0", IndicatorClass.IP_ADDRESS),
            ("255.255.255.255", IndicatorClass.IP_ADDRESS),
            ("d41d8cd98f00b204e9800998ecf8427e", IndicatorClass.FILE_HASH),
            ("a" * 40, IndicatorClass.FILE_HASH),
            ("a" * 64, IndicatorClass.FILE_HASH),
            ("A" * 64, IndicatorClass.FILE_HASH),
            ("evil.test", IndicatorClass.DOMAIN),
            ("sub.evil.co.uk", IndicatorClass.DOMAIN),
            ("xn--80ak6aa92e.com", IndicatorClass.DOMAIN),
            ("https://evil.test/a", IndicatorClass.URL),
            ("http://evil.test", IndicatorClass.URL),
            ("HTTPS://EVIL.TEST/A", IndicatorClass.URL),
        ],
    )
    def test_each_shape_is_recognised(self, value, expected):
        assert classify(value) is expected

    @pytest.mark.parametrize(
        "value",
        ["", "   ", "not a thing!!", "zz", "1.2.3", "a" * 31, "a" * 63, "g" * 64, "no_dots_here"],
    )
    def test_an_unrecognisable_indicator_raises_rather_than_guessing(self, value):
        """An indicator sorted into the wrong class gets the wrong cache
        lifetime and is sent to a provider that cannot answer it, and both
        failures are quiet."""
        with pytest.raises(ValueError):
            classify(value)

    @pytest.mark.parametrize("value", ["999.1.1.1", "1.1.1.256", "300.300.300.300"])
    def test_an_out_of_range_octet_is_named_as_such(self, value):
        with pytest.raises(ValueError, match="octet out of range"):
            classify(value)

    def test_whitespace_is_trimmed(self):
        assert classify("  8.8.8.8  ") is IndicatorClass.IP_ADDRESS

    def test_a_hash_length_that_is_not_a_known_algorithm_is_refused(self):
        """48 hex characters is not md5, sha1 or sha256, and treating it as a
        hash would send it to an endpoint that cannot resolve it."""
        with pytest.raises(ValueError):
            classify("a" * 48)


class TestIndicator:
    def test_parse_sets_the_class_and_trims(self):
        indicator = Indicator.parse("  8.8.8.8 ")
        assert indicator.value == "8.8.8.8"
        assert indicator.kind is IndicatorClass.IP_ADDRESS

    def test_a_hash_key_is_case_folded(self):
        """The same hash in two cases is one indicator. Two cache entries would
        each spend their own quota for one answer."""
        upper = Indicator.parse("D41D8CD98F00B204E9800998ECF8427E")
        lower = Indicator.parse("d41d8cd98f00b204e9800998ecf8427e")
        assert upper.key == lower.key

    def test_a_domain_key_is_case_folded(self):
        assert Indicator.parse("EVIL.TEST").key == Indicator.parse("evil.test").key

    def test_a_url_key_keeps_its_case(self):
        """A path is case significant on most servers, so folding it would
        merge two different URLs into one cache entry."""
        assert Indicator.parse("https://a.test/A").key != Indicator.parse("https://a.test/a").key

    def test_the_key_is_prefixed_by_the_class(self):
        """So an address and a domain that happen to read the same cannot
        collide in one keyspace."""
        assert Indicator.parse("8.8.8.8").key.startswith("ip_address:")
        assert Indicator.parse("evil.test").key.startswith("domain:")

    def test_indicators_are_hashable_and_comparable(self):
        assert Indicator.parse("8.8.8.8") == Indicator.parse("8.8.8.8")
        assert len({Indicator.parse("8.8.8.8"), Indicator.parse("8.8.8.8")}) == 1


class TestEnrichment:
    @pytest.mark.parametrize(
        "disposition",
        [Disposition.MALICIOUS, Disposition.SUSPICIOUS, Disposition.HARMLESS, Disposition.UNKNOWN],
    )
    def test_every_real_answer_is_cacheable(self, disposition):
        enrichment = Enrichment(indicator=Indicator.parse("8.8.8.8"), disposition=disposition)
        assert enrichment.cacheable is True

    def test_an_error_is_not_cacheable(self):
        """An error is a fact about the network, not about the indicator."""
        enrichment = Enrichment(
            indicator=Indicator.parse("8.8.8.8"), disposition=Disposition.ERROR, error="timeout"
        )
        assert enrichment.cacheable is False

    def test_fetched_at_is_timezone_aware(self):
        """A naive timestamp compared against an aware one raises, and a cache
        entry's age is exactly the comparison somebody will make."""
        enrichment = Enrichment(indicator=Indicator.parse("8.8.8.8"), disposition=Disposition.HARMLESS)
        assert enrichment.fetched_at.tzinfo is not None


class TestTruncatedAddresses:
    """A mistyped or truncated address must not classify as a domain.

    Without the rule that a final label may not be all numeric, "192.168.1" is
    a syntactically valid hostname, so it would be sent to a domain endpoint,
    spend a request that can never resolve it, and come back as "no data held"
    rather than "that is not an indicator".
    """

    @pytest.mark.parametrize("value", ["1.2.3", "192.168.1", "10.0.0", "1.2.3.4.5", "8.8"])
    def test_it_is_refused(self, value):
        with pytest.raises(ValueError):
            classify(value)

    @pytest.mark.parametrize("value", ["evil.test", "sub.evil.co.uk", "xn--80ak6aa92e.com", "a1.b2.example"])
    def test_a_real_domain_still_classifies(self, value):
        assert classify(value) is IndicatorClass.DOMAIN
