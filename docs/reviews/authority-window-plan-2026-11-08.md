# Authority windows: one type and a gate (plan, 2026-11-08)

Status: plan. Extends step 3 of
[authority-timing-plan-2026-11-07](authority-timing-plan-2026-11-07.md).

## Problem

Every check builds its validity by hand: `identity.Earlier(...)` chains,
`identity.Fresh(observed, until, now, 5*time.Second)` and literal durations.
On main there are 988 non-test `5*time.Second` literals in 555 files, about
1,400 `Earlier` calls and 266 `Fresh` calls. When ADR-311 moved checks to a
30 s interval, the sites that were missed failed on installed systems one per
CI run:

- capture start, manual live and download sites still bounded at 5 s;
- the regional receiver check returned its local check's later start plus
  30 s, so `Fresh(started, until, now, 30s)` refused its own result
  (`regional-query-bound`, fixed in 8249e79c);
- SQL fences that persist proofs (00035, 00049, 00054/65/73) refused longer
  windows than the Go side produced.

The defect class is "a window that does not start at its own check, or whose
interval differs between producer and consumer".

## Mechanism

1. `identity.Window{From, Until time.Time}` built only by
   `identity.Check(start, interval)`; methods `Narrow(t ...time.Time) Window`
   (only shortens), `Valid(now)`, and `Within(interval)` for consumers.
   `From` is the check's own start and cannot be changed; `Narrow` never
   extends `Until`. A zero Window is invalid.
2. Producers return a `Window` instead of separate `ObservedAt/ValidUntil`
   pairs; consumers call `w.Within(identity.AuthorityRecheckInterval)` instead
   of `Fresh(..., 5*time.Second)`. Both sides then use one named interval.
3. Property test: for every producer converted, `Until <= From + interval`
   for any sequence of inner checks with later starts (the regional bug).
4. SQL: the persisted proofs keep their own bounds; each fence names its
   interval in the migration and a Go test asserts the Go constant equals it,
   so a Go-only change fails locally instead of on an installed run.

## Gate

`make go-check` gains a small script that counts non-test `5*time.Second`
literals used as validity (in `Fresh`/`Add` for `ValidUntil`/`FreshUntil`/
`until`) per file against a checked-in baseline. New ones fail; removing them
lowers the baseline. I/O timeouts (`context.WithTimeout(..., 5*time.Second)`)
stay allowed; they bound blocking work, not authority.

## Rollout

1. Type, property test and gate with the current baseline (no behavior change).
2. Convert the request paths that broke: live watch, capture start/regional
   receiver, downloads, MCP/browser identity. Each conversion deletes its
   per-site patches.
3. Remaining sites as their packages are touched; the baseline only shrinks.

## Complexity checklist

1. Frequent and harmful: yes, about ten installed CI failures on 2026-11-07/08.
2. Maintainer already accepted relaxed intervals (AGENTS.md, ADR-311).
3. All deployments. 4. Precedent: one shared interval constant already exists.
5. No privileges. 6. Fewer failure states (one validity rule).
7. No configuration. 8. No external dependency.
9. No runtime cost. 10. Pure code refactor; rollback by revert.
11. Smaller alternative: the gate alone stops new literals but does not fix
    producer/consumer mismatches; the type is the smallest fix for those.
