# Isolated live-workload ceiling: real PostgreSQL qualification

Run on 2026-11-10 from the PR #208 working tree before commit `c6f59661`.

Command:

```bash
TMPDIR=/home/phil/.cache/asservat-build/tmp GOFLAGS=-p=2 \
  python3 scripts/test-custody.py \
  --run '^TestLiveWatchLedgerWithRealServices$' \
  --result-name live-workload-ceiling
```

Result: exit 0. `TestLiveWatchLedgerWithRealServices` passed in 18.74 seconds;
the package completed in 19.812 seconds. The environment records the selected
test, unchanged source hashes during the run and no cleanup failures.

Three installation slots and three principal slots leave the two-slot workload
ceiling as the only binding limit. Distinct principals fill that workload's two
controls; a third principal is refused with `live.ErrCapacity`. A different
workload is admitted. Closing one original control permits the refused workload
to open its replacement slot.

The four controls close without spend and expire. Bounded pruning removes four
controls and six fully refilled accounts, allowing the original limits to be
restored for every pre-existing assertion in the fixture. This follows the SQL
contract that numeric limit replacement waits for old receipts/accounts rather
than resetting them.

This is SQL control-facet qualification only. It is not installed/native,
cross-workload scheduling, overload or sustained-throughput qualification.

Evidence:

- `live-workload-ceiling.log`: focused Go test output.
- `live-workload-ceiling-environment.json`: selected test, pinned services,
  source hashes, exit status and cleanup report.
