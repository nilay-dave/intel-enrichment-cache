## What this changes

## Why

## If this touches quota, lifetimes or thresholds

These decide how much of a caller's allowance gets spent and what verdict comes
back, so they are a minor version at least.

- [ ] `make bench` run, and the change in requests per thousand lookups stated here
- [ ] Any new published figure carries a marker and matches `docs/metrics.json`
- [ ] A new rate preset records the documentation it came from and the date
- [ ] A figure that is this library's choice rather than a vendor's is labelled in the preset note

## If this touches anything concurrent

- [ ] No per call fact is inferred from a shared counter (this has been wrong twice here)
- [ ] A cancellation path has a test: a cancelled first caller, and a cancelled waiter
- [ ] No test pass depends on a real millisecond margin

## Checks

- [ ] `make verify` passes
- [ ] No test reaches a network
- [ ] CHANGELOG updated, with the version bump the change actually warrants
