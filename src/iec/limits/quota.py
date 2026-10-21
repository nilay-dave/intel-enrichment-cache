"""The daily quota, counted over a rolling window and kept on disk.

Two decisions here, and both are about failing in the safe direction.

**Rolling window, not a calendar day.** Providers document a daily allowance
without always saying how the day is bounded. The asymmetry decides it. If the
provider resets at midnight and this counts a rolling 24 hours, the client
under-spends slightly and nothing breaks. If the provider rolls and this counts
calendar days, the client can spend its whole allowance at 23:00 and the whole
of the next one at 00:01, which is double the documented rate inside two hours
and is how an account gets suspended. The cheap mistake is the one to make.

**On disk, not in memory.** A SOAR worker restarts: on a deploy, on an OOM, on
a pod reschedule. An in memory counter resets with it, and a client that has
forgotten what it spent will happily spend it again. The whole point of local
quota accounting is to avoid finding out the limit from the provider, so
accounting that evaporates on restart is accounting that does not do its job
on exactly the days it matters.

Storage is SQLite because this library already needs it for the cache. A second
store would be a second thing to configure, back up and get wrong.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable
from contextlib import closing
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS spend (
    provider  TEXT    NOT NULL,
    spent_at  REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS spend_provider_time ON spend (provider, spent_at);
"""


class QuotaExhausted(Exception):
    """The local accounting says there is nothing left to spend."""

    def __init__(self, provider: str, limit: int, window_seconds: float, retry_after: float) -> None:
        super().__init__(
            f"{provider}: {limit} requests per {window_seconds / 3600:.0f}h is spent; "
            f"next one is available in {retry_after / 60:.0f} minutes"
        )
        self.provider = provider
        self.limit = limit
        self.window_seconds = window_seconds
        self.retry_after = retry_after


class DailyQuota:
    """A rolling window counter, persisted.

    Writes are synchronous and one row per request. At a few hundred requests a
    day that is nothing, and it means the record of a spend is durable before
    the request that spends it goes out. Recording after the response would
    lose the spend on a crash mid request, which is the moment the count
    matters most.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._path = Path(path)
        self._clock = clock
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            connection.executescript(SCHEMA)
            connection.commit()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=5.0)
        # WAL so a reader does not block the writer. A SOAR deployment runs
        # several workers against one volume often enough to be worth it.
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        return connection

    def spent(self, provider: str, window_seconds: float) -> int:
        """How many requests fall inside the window ending now."""
        cutoff = self._clock() - window_seconds
        with closing(self._connect()) as connection:
            self._prune(connection, provider, cutoff)
            row = connection.execute(
                "SELECT COUNT(*) FROM spend WHERE provider = ? AND spent_at > ?",
                (provider, cutoff),
            ).fetchone()
            connection.commit()
        return int(row[0])

    @staticmethod
    def _prune(connection: sqlite3.Connection, provider: str, cutoff: float) -> None:
        # Pruned on read rather than on a timer. The table is only ever read
        # just before a request, so there is no state to let it grow without
        # bound and no background task to own.
        connection.execute("DELETE FROM spend WHERE provider = ? AND spent_at <= ?", (provider, cutoff))

    def remaining(self, provider: str, limit: int, window_seconds: float) -> int:
        return max(0, limit - self.spent(provider, window_seconds))

    def retry_after(self, provider: str, window_seconds: float) -> float:
        """Seconds until the oldest request in the window falls out of it."""
        cutoff = self._clock() - window_seconds
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT MIN(spent_at) FROM spend WHERE provider = ? AND spent_at > ?",
                (provider, cutoff),
            ).fetchone()
        if row is None or row[0] is None:
            return 0.0
        return max(0.0, row[0] + window_seconds - self._clock())

    def charge(self, provider: str, limit: int, window_seconds: float) -> int:
        """Record one request, or raise QuotaExhausted.

        Raising rather than returning False, because a caller that forgets to
        check a boolean sends the request anyway and the accounting silently
        stops meaning anything. An exception cannot be ignored by accident.
        """
        now = self._clock()
        cutoff = now - window_seconds
        with closing(self._connect()) as connection:
            # IMMEDIATE takes the write lock up front, so the count and the
            # insert cannot be split by another worker counting the same free
            # slot and inserting into it too.
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._prune(connection, provider, cutoff)
                used = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM spend WHERE provider = ? AND spent_at > ?",
                        (provider, cutoff),
                    ).fetchone()[0]
                )
                if used >= limit:
                    oldest = connection.execute(
                        "SELECT MIN(spent_at) FROM spend WHERE provider = ? AND spent_at > ?",
                        (provider, cutoff),
                    ).fetchone()[0]
                    connection.rollback()
                    wait = max(0.0, (oldest or now) + window_seconds - now)
                    raise QuotaExhausted(provider, limit, window_seconds, wait)
                connection.execute("INSERT INTO spend (provider, spent_at) VALUES (?, ?)", (provider, now))
                connection.commit()
                return limit - used - 1
            except QuotaExhausted:
                raise
            except Exception:
                connection.rollback()
                raise

    def refund(self, provider: str) -> bool:
        """Give back the most recent spend.

        Used when a request was charged and then never reached the provider,
        for example because the connection failed before any bytes went out.
        Charging before sending is the right order, so there has to be a way
        to undo one.
        """
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT rowid FROM spend WHERE provider = ? ORDER BY spent_at DESC LIMIT 1", (provider,)
            ).fetchone()
            if row is None:
                connection.rollback()
                return False
            connection.execute("DELETE FROM spend WHERE rowid = ?", (row[0],))
            connection.commit()
            return True
