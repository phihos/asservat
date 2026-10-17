# Prepaid Stop retirement — SQL47 / ADR124

Guarded source package only. No live repository edits or external fixtures were
performed by this agent. Generated custodydb output is a compile overlay and is
not included: regenerate against the combined parent schema after integration.

## Implemented

New explicitly qualified Stop backing binds a closed writer protocol. A real
successful conditional PUT, exact verified GET and joined producer yield positive
completion; lost/unknown/412/Find cannot manufacture it. Original Stop bytes stay
unchanged. Historical unbound obligations are not upgraded.

The original cutoff permanently closes unused or unclaimed expired decisions;
the latter is recorded as missed audit (`unwritten`). Issued unknown writers stay
charged. Proven originals are purged before one purpose-specific signed encrypted
retirement certificate. Separate read/open/public-key verification consumes one
of two prepaid SQL attempts before provider access. Exact positive certificate
completion, independently acknowledged complete absence and atomic SQL retirement
precede release into the original backed cooling history. H=0 and H>0 retain
separate correct paths; parent download/output/read/worker accounting is untouched.

The same change fixes pending-audit starvation: attempt independent selected
obligations even after one provider failure, preserve the original five-second
pass, and exclude exhausted/expired-unclaimed/closed/cutoff records from its
sixteen active slots while retaining their charges. Selection prioritizes new
writes and then the least-used lookup budgets, without refilling either.

Role, phase and lease boundaries are explicit. The trigger's admission clock is
read after potentially blocking backing locks. Pool→backing order is shared with
cleanup; cleanup never takes a parent allocation/artifact row lock. Full order
and intentional MVCC-only reads are documented in the architecture contract.

## Actual checks

- `pending-before.log`: terminal1, meaningful existing-code failure: first failed
  Stop prevented the independent second obligation from being attempted.
- `verifier-before.log`: terminal1 against the staged pre-spend algorithm:
  provider open happened with zero prepaid verifier claims.
- `regressions-after.log`: terminal0, focused race regressions including both fixes.
- `second-race.log`: terminal0 for six packages (domain/audit, application/evidence,
  objectstore, framed, jose, postgres). Domain/objectstore/jose were cached passes;
  evidence, framed and postgres ran in 1.550s, 6.933s and 1.196s.
- `vet.log`: terminal0, the same six packages plus integration source.
- `integration-final-compile.log`: terminal0, integration package compile only,
  `[no tests to run]`; this is not a native qualification.
- `sqlc-final.log`: terminal0 with the pinned tool. The earlier `sqlc-third.log`
  caught an ambiguous correlated pending-query root; explicit aliases fixed it.
  Earlier first Postgres compilation also exposed sqlc's unknown table-function
  SELECT-star shape; the query now names its typed columns.

No full repository/spec/architecture gates or native tests were run in this stage.
Parent owns combined gates and real service execution. Source hashes and guarded
base hashes are in manifest.json; the package contains 23 source paths.

## Native fixture source awaiting parent execution

The narrow `qualifyDownloadStopLifecycle` hook is adjacent to the existing Stop
hook inside the already-selected context publication fixture. New source covers
actual SQL/S3/codec/signatures, H=0/H>0 using real clocks, positive/unused/unwritten/
unknown writers, exact roles, exhausted lookup selection, verifier attempt
exhaustion, irreversible no-claim closure, and a real `pg_blocking_pids`-observed
backing lock that crosses the pool deadline and must roll back all reservation.

It also runs positive finalization in an uncommitted SQL transaction and rolls it
back, verifies original state/accounting, then finalizes. Four concurrent history
drains must release exactly the original three healthy records once while the
unknown record and parent allocation stay charged. Helper pools close explicitly;
owned concurrent work joins. Policy/H/footprint and initial authority inputs are
explicitly synthetic, not a pgBackRest/backend-capacity qualification. The fixture
waits for original retention times (~65–80 seconds); parent has planned an explicit
600s/660s aggregate suite bound without changing authority or cleanup deadlines.

## Merge and remaining work

Shared schema head/inventory/roles base on live46. Add the decision/architecture
index and progress entries centrally; preserve parent48's separately staged audit
verifier compatibility fix. This payload owns no41/48 files.

Protected policy/signer-purpose provisioning, backend IAM/backup/WAL qualification,
actual runtime supervision and independently qualified unknown-writer recovery
remain required. Legacy Stop rows and parent download metadata retain their own
cleanup obligations. Supported logical recovery history is bounded; no physical
sanitization claim is made. The chart and public runtime stay disabled. Continue
the actual installed workflow after the owned native qualification succeeds.
