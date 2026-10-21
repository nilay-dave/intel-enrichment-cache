"""A SQLite backed cache, kept off the event loop.

SQLite's driver is blocking, so calling it from a coroutine stalls every other
task in the worker for the duration of the query. On a cache hit that is a
fraction of a millisecond and easy to shrug at, right up to the point where the
file is on network storage or another process holds the write lock, and then a
single enrichment stalls the whole worker. So every call goes through a thread.

Connections are thread local rather than shared. One connection behind a lock
would serialise cache reads across the thread pool, which defeats the point of
moving them off the loop; a connection per call is correct but pays the open
cost on every lookup. Thread local gives both: each worker thread opens once
and reuses, and SQLite's own threading rule, that a connection belongs to the
thread that made it, is satisfied by construction rather than by a promise.

WAL mode because readers must not block the writer. A SOAR deployment with
several workers against one volume is common enough that the default rollback
journal, where a write excludes all readers, would turn the cache into the
contention point it was added to remove.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from iec.cache.store import CacheStats
from iec.models import Disposition, Enrichment, Indicator, IndicatorClass, ProviderVerdict, Source

SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    key          TEXT    PRIMARY KEY,
    kind         TEXT    NOT NULL,
    value        TEXT    NOT NULL,
    disposition  TEXT    NOT NULL,
    verdicts     TEXT    NOT NULL,
    fetched_at   REAL    NOT NULL,
    expires_at   REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS entries_expiry ON entries (expires_at);
"""


class SqliteCache:
    """Per indicator cache with a lifetime per entry."""

    def __init__(self, path: Path | str, *, clock: Callable[[], float] = time.time) -> None:
        self._path = Path(path)
        self._clock = clock
        self._local = threading.local()
        # Every connection ever opened, so close() can close all of them. The
        # thread local alone was not enough: close() ran on the calling thread
        # and released that thread's connection, leaving one open per worker
        # thread in the pool. In a long running worker those are reused and the
        # leak is invisible; in a process that builds and discards caches it is
        # a file handle each time, which is how it showed up, as a
        # ResourceWarning in the test suite.
        self._connections: list[sqlite3.Connection] = []
        self._connections_lock = threading.Lock()
        self._closed = False
        self._stats = CacheStats()
        if self._path.parent != Path():
            self._path.parent.mkdir(parents=True, exist_ok=True)
        connection = self._connection()
        connection.executescript(SCHEMA)
        connection.commit()

    def _connection(self) -> sqlite3.Connection:
        if self._closed:
            # Reopening on demand would make close() a suggestion: a caller who
            # released the file would find the next lookup had taken it again,
            # and the leak close() exists to fix would be back with no sign of
            # it. Better to fail where the mistake is.
            raise RuntimeError("this cache is closed")
        existing = getattr(self._local, "connection", None)
        if existing is not None:
            return existing
        # check_same_thread is off so that close() can close a connection from
        # a thread other than the one that opened it. The safety that flag
        # normally provides is kept by construction instead: a connection is
        # only ever handed to the thread it was created for, because it lives
        # in thread local storage, so no two threads use one concurrently. The
        # flag permits the teardown, not shared use.
        connection = sqlite3.connect(self._path, timeout=5.0, check_same_thread=False)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.row_factory = sqlite3.Row
        self._local.connection = connection
        with self._connections_lock:
            self._connections.append(connection)
        return connection

    @property
    def stats(self) -> CacheStats:
        return self._stats

    # Synchronous bodies, so the thread hop is in one place and the logic can
    # be tested without an event loop.

    def _get(self, key: str) -> Enrichment | None:
        now = self._clock()
        row = self._connection().execute("SELECT * FROM entries WHERE key = ?", (key,)).fetchone()
        if row is None:
            self._stats.misses += 1
            return None
        if row["expires_at"] <= now:
            # Deleted on the way past rather than by a sweeper. The only moment
            # anyone cares about this key is now, and a background task would
            # be a thing to own for no gain.
            self._connection().execute("DELETE FROM entries WHERE key = ?", (key,))
            self._connection().commit()
            self._stats.expired += 1
            self._stats.misses += 1
            return None
        self._stats.hits += 1
        return _from_row(row)

    def _put(self, enrichment: Enrichment, ttl_seconds: float) -> bool:
        if not enrichment.cacheable:
            # An error is a fact about the network, not about the indicator.
            # Storing it would pin a transient failure to the indicator for the
            # length of a TTL, and the indicator would look clean until it
            # expired.
            self._stats.rejected += 1
            return False
        if ttl_seconds <= 0:
            self._stats.rejected += 1
            return False
        now = self._clock()
        self._connection().execute(
            "INSERT INTO entries (key, kind, value, disposition, verdicts, fetched_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET disposition=excluded.disposition, verdicts=excluded.verdicts, "
            "fetched_at=excluded.fetched_at, expires_at=excluded.expires_at",
            (
                enrichment.indicator.key,
                enrichment.indicator.kind.value,
                enrichment.indicator.value,
                enrichment.disposition.value,
                json.dumps([asdict(verdict) for verdict in enrichment.verdicts]),
                now,
                now + ttl_seconds,
            ),
        )
        self._connection().commit()
        self._stats.stores += 1
        return True

    def _purge_expired(self) -> int:
        cursor = self._connection().execute("DELETE FROM entries WHERE expires_at <= ?", (self._clock(),))
        self._connection().commit()
        return cursor.rowcount

    def _count(self) -> int:
        return int(self._connection().execute("SELECT COUNT(*) FROM entries").fetchone()[0])

    async def get(self, key: str) -> Enrichment | None:
        return await asyncio.to_thread(self._get, key)

    async def put(self, enrichment: Enrichment, ttl_seconds: float) -> bool:
        return await asyncio.to_thread(self._put, enrichment, ttl_seconds)

    async def purge_expired(self) -> int:
        return await asyncio.to_thread(self._purge_expired)

    async def count(self) -> int:
        return await asyncio.to_thread(self._count)

    def close(self) -> None:
        """Close every connection this cache opened, on any thread."""
        self._closed = True
        with self._connections_lock:
            connections, self._connections = self._connections, []
        for connection in connections:
            try:
                connection.close()
            except sqlite3.Error:
                # A connection already closed, or whose thread died mid
                # statement. Nothing useful to do, and raising here would turn
                # a tidy up into a failure.
                pass
        self._local.connection = None

    def __enter__(self) -> SqliteCache:
        return self

    def __exit__(self, *exception: object) -> None:
        self.close()


def _from_row(row: sqlite3.Row) -> Enrichment:
    verdicts = tuple(
        ProviderVerdict(
            provider=item["provider"],
            disposition=Disposition(item["disposition"]),
            score=item["score"],
            detail=item.get("detail") or {},
        )
        for item in json.loads(row["verdicts"])
    )
    return Enrichment(
        indicator=Indicator(value=row["value"], kind=IndicatorClass(row["kind"])),
        disposition=Disposition(row["disposition"]),
        verdicts=verdicts,
        source=Source.CACHE,
        fetched_at=datetime.fromtimestamp(row["fetched_at"], UTC),
    )
