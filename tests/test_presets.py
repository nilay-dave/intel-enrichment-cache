import datetime as dt

import pytest

from iec.limits.presets import PRESETS, Preset, preset


def test_every_preset_is_reachable_by_its_own_name():
    for name, entry in PRESETS.items():
        assert preset(name) is entry
        assert entry.name == name


def test_an_unknown_preset_lists_the_alternatives():
    with pytest.raises(KeyError, match="available: abuseipdb-check-free"):
        preset("virustotal-premium")


@pytest.mark.parametrize("entry", list(PRESETS.values()), ids=lambda entry: entry.name)
class TestProvenance:
    """Every published limit has to say where it came from.

    A figure in a library with no provenance is a figure nobody can audit, and
    a reader who wants to know whether it is still true needs to know where to
    look.
    """

    def test_it_names_a_documentation_source(self, entry: Preset):
        assert entry.source
        assert "." in entry.source, "the source should name a documentation site"

    def test_the_date_it_was_read_is_a_real_date(self, entry: Preset):
        dt.date.fromisoformat(entry.checked_on)

    def test_it_tells_the_caller_to_verify_against_their_own_account(self, entry: Preset):
        """None of these can be checked from inside this library, and a caller
        on a paid tier has different numbers entirely."""
        assert entry.verify_against_your_account is True

    def test_the_limits_are_positive(self, entry: Preset):
        assert entry.rate.allowance > 0
        assert entry.daily_limit is None or entry.daily_limit > 0

    def test_the_daily_allowance_is_not_smaller_than_the_short_window_one(self, entry: Preset):
        """A daily limit below what the per minute rate allows in a day is
        fine, but a daily limit below a single burst would mean the burst can
        never be spent, which would be a transcription error."""
        if entry.daily_limit is not None:
            assert entry.daily_limit >= entry.rate.capacity

    def test_describe_names_the_source_and_the_date(self, entry: Preset):
        rendered = entry.describe()
        assert entry.source in rendered
        assert entry.checked_on in rendered


def test_figures_this_library_chose_are_labelled_as_such():
    """AbuseIPDB documents a daily limit per endpoint and no short window one,
    so the per minute pacing is this library's choice. Presenting it as the
    vendor's number would be inventing a fact about someone else's API."""
    for name in ("abuseipdb-check-free", "abuseipdb-reports-free"):
        assert "pacing choice" in preset(name).note


def test_the_virustotal_preset_matches_its_documented_figures():
    """500 a day and 4 a minute, which is what their public versus premium
    page states."""
    entry = preset("virustotal-public")
    assert entry.rate.allowance == 4
    assert entry.rate.per_seconds == 60.0
    assert entry.daily_limit == 500


def test_the_two_abuseipdb_endpoints_have_separate_budgets():
    """A client treating them as one budget exhausts the smaller one first
    without noticing, which is why they are two presets."""
    assert preset("abuseipdb-check-free").daily_limit == 1_000
    assert preset("abuseipdb-reports-free").daily_limit == 100


def test_the_rolling_window_choice_is_explained_where_it_is_made():
    assert "rolling" in preset("virustotal-public").note.lower()
