# sqlite3.Connection as a context manager commits or rolls back a
# transaction. It does not close the connection, which is a footgun worth
# naming because three tests in this repository used it that way and leaked a
# handle each. contextlib.closing is what closes. The library itself always
# used closing; only these tests were wrong.
import sqlite3
from contextlib import closing

import pytest

from iec.limits.quota import DailyQuota, QuotaExhausted

DAY = 86_400.0


class Clock:
    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def quota(tmp_path):
    clock = Clock()
    return clock, DailyQuota(tmp_path / "quota.sqlite", clock=clock)


def test_charging_decrements_what_is_left(quota):
    _, store = quota
    assert store.charge("vt", 3, DAY) == 2
    assert store.charge("vt", 3, DAY) == 1
    assert store.charge("vt", 3, DAY) == 0
    assert store.remaining("vt", 3, DAY) == 0


def test_charging_past_the_limit_raises_rather_than_returning_false(quota):
    """A caller who forgets to check a boolean sends the request anyway, and
    the accounting silently stops meaning anything."""
    _, store = quota
    store.charge("vt", 1, DAY)
    with pytest.raises(QuotaExhausted) as caught:
        store.charge("vt", 1, DAY)
    assert caught.value.provider == "vt"
    assert caught.value.limit == 1


def test_the_refusal_says_when_to_come_back(quota):
    clock, store = quota
    store.charge("vt", 1, DAY)
    clock.now += 3600.0
    with pytest.raises(QuotaExhausted) as caught:
        store.charge("vt", 1, DAY)
    # The spend was an hour ago, so it leaves the window in 23 hours.
    assert caught.value.retry_after == pytest.approx(DAY - 3600.0)


def test_providers_have_separate_budgets(quota):
    _, store = quota
    store.charge("vt", 1, DAY)
    assert store.charge("abuseipdb", 1, DAY) == 0
    assert store.spent("vt", DAY) == 1


def test_the_window_rolls_rather_than_resetting_on_a_boundary(quota):
    """The asymmetry this decision rests on.

    If the provider resets at midnight and this rolls, the client under spends
    and nothing breaks. If the provider rolls and this reset at midnight, the
    client could spend a full allowance at 23:00 and another at 00:01.
    """
    clock, store = quota
    for _ in range(3):
        store.charge("vt", 3, DAY)
    clock.now += DAY - 1
    assert store.remaining("vt", 3, DAY) == 0
    clock.now += 2
    assert store.remaining("vt", 3, DAY) == 3


def test_spends_leave_the_window_one_at_a_time(quota):
    clock, store = quota
    store.charge("vt", 3, DAY)
    clock.now += 3600.0
    store.charge("vt", 3, DAY)
    clock.now += 3600.0
    store.charge("vt", 3, DAY)
    assert store.remaining("vt", 3, DAY) == 0
    clock.now += DAY - 7200.0 + 1
    assert store.remaining("vt", 3, DAY) == 1


def test_accounting_survives_a_restart(tmp_path):
    """A SOAR worker restarts on a deploy, an OOM or a reschedule. An in memory
    counter resets with it and the client spends its allowance twice."""
    clock = Clock()
    path = tmp_path / "quota.sqlite"
    first = DailyQuota(path, clock=clock)
    for _ in range(4):
        first.charge("vt", 5, DAY)

    second = DailyQuota(path, clock=clock)
    assert second.spent("vt", DAY) == 4
    assert second.charge("vt", 5, DAY) == 0
    with pytest.raises(QuotaExhausted):
        second.charge("vt", 5, DAY)


def test_retry_after_is_zero_with_nothing_spent(quota):
    _, store = quota
    assert store.retry_after("vt", DAY) == 0.0


def test_a_refund_gives_back_the_most_recent_spend(quota):
    """Charging happens before the request goes out, which is the right order,
    so there has to be a way to undo one that never left."""
    _, store = quota
    store.charge("vt", 1, DAY)
    assert store.refund("vt") is True
    assert store.charge("vt", 1, DAY) == 0


def test_a_refund_with_nothing_spent_reports_so(quota):
    _, store = quota
    assert store.refund("vt") is False


def test_old_rows_are_pruned_rather_than_accumulating(quota):
    clock, store = quota
    for _ in range(10):
        store.charge("vt", 50, DAY)
    clock.now += DAY + 1
    store.spent("vt", DAY)
    with closing(sqlite3.connect(store._path)) as connection:
        remaining = connection.execute("SELECT COUNT(*) FROM spend").fetchone()[0]
    assert remaining == 0


def test_the_database_is_created_with_its_parent_directory(tmp_path):
    store = DailyQuota(tmp_path / "nested" / "deeper" / "quota.sqlite")
    assert store.charge("vt", 1, DAY) == 0


def test_write_ahead_logging_is_on(quota):
    _, store = quota
    with closing(sqlite3.connect(store._path)) as connection:
        mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode.lower() == "wal"
