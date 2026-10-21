# Security policy

## Reporting

Report a vulnerability through GitHub's private vulnerability reporting on this
repository, under Security, rather than by opening an issue. Expect an
acknowledgement within three working days.

## What this library is careful about

**It cannot submit anything.** Both provider clients are read only by
construction: no upload, no report, no vote. An analyst calling an enrichment
function does not expect a copy of a customer's file to leave the building, or
their own egress address to be published as an abuser. This is a property of
the code, not a configuration setting.

**API keys are never logged or stored.** They are held in the provider instance
and sent in a request header. The library writes two files, a cache and a quota
ledger, and neither contains a credential.

**The cache holds indicators and verdicts.** On a shared volume that is a
record of what an organisation has been investigating, which is worth
protecting even though none of it is a secret. Point `SqliteCache` somewhere
with appropriate permissions.

**An error is never cached.** Beyond correctness this matters for safety: a
cached failure would read as an unresolved indicator for the length of a
lifetime, which is the quiet way a detection gets lost.

**A provider's 429 is a distinct exception type.** Reaching one means the local
accounting was wrong, and repeated breaches are what gets a key suspended on
some tiers rather than throttled. The library treats it as a configuration
problem to surface, not an error to retry.

## What is out of scope

- The verdict a provider returns. This library reports what it was told, under
  thresholds documented in `providers/base.py` and configurable.
- The rate presets. They were read from vendor documentation on a recorded
  date, every preset says so, and every one carries
  `verify_against_your_account` because none of them can be checked from
  inside this library.

## Supported versions

The most recent minor release.
