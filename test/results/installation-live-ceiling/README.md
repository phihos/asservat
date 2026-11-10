# Installation-wide live-view ceiling: real PostgreSQL qualification

Run on 2026-11-10 from the corrected PR #205 working tree, before commit
`eeca334d` (`test: qualify installation-wide live ceiling in SQL`).

Command:

```bash
TMPDIR=/home/phil/.cache/asservat-build/tmp GOFLAGS=-p=2 \
  python3 scripts/test-custody.py \
  --run '^TestLiveWatchLedgerWithRealServices$' \
  --result-name installation-live-ceiling
```

Result: exit 0. `TestLiveWatchLedgerWithRealServices` passed in 10.53 seconds;
the package completed in 11.596 seconds. The environment records the selected
test, unchanged source hashes during the run and no cleanup failures.

The existing real-PostgreSQL fixture fills both installation-wide watch slots
with two distinct principal keys, each within its one-principal-slot limit.
A third distinct principal must receive `live.ErrCapacity`. Closing the second
principal's control releases its installation slot. The original four controls
then retain the existing expiry/debt expectations `n == 4` and `a == 2`.

This is SQL control-facet qualification only. It does not qualify an installed
runtime, multi-principal React/MCP behavior, overload, incident priority or
sustained throughput. Native run 42722762721 is not a pass: its separate
installed suite was invalid because `PrincipalWatches=4` exceeded installation
`Watches=2`. That suite was removed rather than weakening the capacity model.

Evidence:

- `installation-live-ceiling.log`: focused Go test output.
- `installation-live-ceiling-environment.json`: selected test, pinned service
  images, source hashes, exit status and cleanup report.
