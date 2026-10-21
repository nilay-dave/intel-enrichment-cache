# intel enrichment cache

A threat intelligence client for a SOAR worker, built around the constraint
that actually bites: a free tier allows a few hundred lookups a day, and an
alert pipeline produces more than that before lunch.

So the library is organised as a series of stages that each stop work reaching
the next, and the only interesting measurement is how much work never becomes a
request.

```python
from iec import EnrichmentClient, ProviderBudget, SqliteCache, VirusTotal, preset

client = EnrichmentClient(
    [ProviderBudget.from_preset(VirusTotal(api_key), preset("virustotal-public"))],
    cache=SqliteCache("intel-cache.sqlite"),
    quota="intel-quota.sqlite",
)

verdict = await client.enrich("8.8.8.8")
print(verdict.disposition, verdict.source)
```

## Start here

- [Measurements](measurements.md) is what the cache, the coalescer and the
  hedger are each worth, and which of those figures are simulated.
- [Where the numbers come from](sources.md) separates the three kinds of figure
  in this repository: limits read from a vendor's documentation, choices this
  library made, and things that were measured.
- [Limitations](limitations.md) is what it does not do, each with the condition
  that would trigger building it.
- The [decision records](adr/adr-001-cache-lifetime.md) include one that
  publishes a measurement arguing against its own conclusion, and one about the
  four separate ways the benchmark was wrong before it was believable.

## The design in one paragraph

Five stages, cheapest first: a cache read, a dictionary lookup to collapse
concurrent duplicates, a durable quota check that refuses before anything
leaves the process, a token bucket that paces what does leave, and finally the
request. Errors are never cached, because an error is a fact about the network
rather than about the indicator. A partial answer is returned rather than
discarded, because an analyst holding one verdict and a note about the other
source is better served than one holding an exception. The worst verdict wins,
because averaging a detection with an absence of one produces a number that
means nothing.

## The thing most libraries get wrong

Hedging. Sending a duplicate request when the first is slow is close to free
against an unmetered service and is not free against a metered one, so a hedge
here has to clear three gates: the first request is still outstanding, a token
is free without waiting, and enough of the daily allowance remains. Below the
floor the hedge is refused, because the last of the budget belongs to alerts
with no answer at all rather than to a faster answer for one already on its
way.

This library's own docstring was wrong about the size of that cost until the
benchmark corrected it, which is written up in
[measurements](measurements.md) rather than quietly fixed.
