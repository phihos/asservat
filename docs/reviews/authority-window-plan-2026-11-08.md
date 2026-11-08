# Authority windows: one type and a gate (plan, 2026-11-08)

Status: plan; rollout step 1 implemented. Extends step 3 of
[authority-timing-plan-2026-11-07](authority-timing-plan-2026-11-07.md).

## Problem

Every check builds its validity by hand: `identity.Earlier(...)` chains,
`identity.Fresh(observed, until, now, 5*time.Second)` and literal durations.
On main (c512de5c) a plain search of non-test Go files under `internal/` finds
about 990 `5*time.Second` literals in about 550 files (validity and I/O
timeouts together), about 1,400 `Earlier` calls and about 270 `Fresh` calls.
These are orders of magnitude, not the gate baseline (see Gate). When ADR-311 moved checks to a
30 s interval, the sites that were missed failed on installed systems one per
CI run:

- capture start, manual live and download sites still bounded at 5 s;
- the regional receiver check returned its local check's later start plus
  30 s, so `Fresh(started, until, now, 30s)` refused its own result
  (`regional-query-bound`, fixed in PR #174);
- SQL fences that persist proofs (00035, 00049, 00054/65/73) refused longer
  windows than the Go side produced.

The defect class is "a window that does not start at its own check, or whose
interval differs between producer and consumer".

## Mechanism

1. `identity.Window{From, Until time.Time, Kind}` built only by
   `identity.Check(start, kind)`; methods `Narrow(t ...time.Time) Window`
   (only shortens), `Valid(now)`. `From` is the check's own start and cannot be
   changed; `Narrow` never extends `Until`. A zero Window is invalid.
2. `Kind` names the interval, one constant per kind, so producer and consumer
   cannot disagree: `Recheck` (ADR-311, 30 s), `PolicyObservation` (60 s),
   and `SQLFenced` (5 s, only for proofs that SQL fences persist, see 4).
   Consumers call `w.Valid(now)`; the window's own kind supplies the bound
   instead of a literal at the call site. Producers return a `Window` instead
   of separate `ObservedAt/ValidUntil` pairs.
3. Property test: for every producer converted, `Until <= From + interval`
   for any sequence of inner checks with later starts (the regional bug).
4. SQL: the persisted proofs keep their own bounds; each fence names its
   interval in the migration and a Go test asserts the Go constant equals it,
   so a Go-only change fails locally instead of on an installed run.

## Gate

`make go-check` gains a small script that counts, per non-test file, duration
literals passed to `identity.Fresh`/`value.Fresh` or added to a time assigned
to a `ValidUntil`/`FreshUntil`/`until` name (go/ast, not grep). Its first run
writes the checked-in baseline; that file, not the numbers above, is the
gate. New sites fail; converting sites lowers the baseline. I/O timeouts (`context.WithTimeout(..., 5*time.Second)`)
stay allowed; they bound blocking work, not authority.

## Rollout

1. Type, property test and gate with the current baseline (no behavior change).
   Done: `identity.Window` (internal/domain/identity/window.go), the SQL fence
   test for `context_execution_check`, `capacity_recovery_current` and the two
   connector recovery locks, `make authority-window-check` (part of go-check
   and pre-push) with `scripts/authority-windows-baseline.txt` (362 sites in
   262 files). Worked example: `fleet.APIContextReceiver` carries a `Window`;
   the regional receiver check builds it at its own start instead of the
   PR #174 clip.
2. Convert the request paths that broke: live watch, capture start/regional
   receiver, downloads, MCP/browser identity. Each conversion deletes its
   per-site patches.
3. Remaining sites as their packages are touched; the baseline only shrinks.

## Complexity checklist

1. Frequent and harmful: yes, the installed live-watch and capture-start runs of
   2026-11-07/08 (PR #174) failed repeatedly on this class.
2. Maintainer already accepted relaxed intervals (AGENTS.md, ADR-311).
3. All deployments. 4. Precedent: one shared interval constant already exists.
5. No privileges. 6. Fewer failure states (one validity rule).
7. No configuration. 8. No external dependency.
9. No runtime cost. 10. Pure code refactor; rollback by revert.
11. Smaller alternative: the gate alone stops new literals but does not fix
    producer/consumer mismatches; the type is the smallest fix for those.
