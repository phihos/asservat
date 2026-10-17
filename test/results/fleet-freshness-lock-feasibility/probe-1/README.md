# PostgreSQL 18 fleet-view lock feasibility

Staged only. No service, query, build, migration or native test has run for this
probe. The parent must review the exact manifest and allocate the sole native
slot before invoking:

```sh
python /home/phil/.cache/asservat-build/planning/fleet-freshness-lock-probe-20261014/probe.py --parent-exclusive-slot-allocated
```

The result directory must not already exist. The probe uses the already local
PostgreSQL 18 image pinned by the repository's owned fixtures. It pulls/builds
nothing, publishes no port, creates no network and mounts no host directory. The
unique labelled container owns one anonymous database volume; cleanup verifies
the exact container identity and volume absence, and joins every host command.
First signals are recorded, repeated signals cannot interrupt cleanup, and an
unknown create reply plus absence is a failed/uncertain cleanup result. All SQL,
logs, source snapshots, payloads, server/image identity and terminal checks are
retained under `checks/probe-1`. Do not rerun into or erase that directory.

`schema.sql` is a synthetic fixture, **not a migration or production producer**.
It copies the current base constraints and exact nine-column legacy view, then
tests a MATERIALIZED observation CTE plus authority-table outer relation. It
keeps the current names/order/types, including the view composite type used by
PL/pgSQL. The earlier proposal's reference to ten columns was a counting error.
Missing/mismatched binding returns `recovery_blocked=true` and two equal finite
epoch dates, never SQL NULL or legacy positive dates.

The real non-superuser consumer receives only view SELECT, view
UPDATE(installation_id), and the exact analogous privilege for the synthetic
joined permission row. It has no SELECT/UPDATE on either base table. A separate
SELECT-only role must fail the lock. The tested forms are full SHARE, full
UPDATE, id-only SHARE, SHARE/UPDATE NOWAIT, joined SHARE OF view, unqualified
joined SHARE, and invoker PL/pgSQL composite selection. After each retained lock,
a separate credential writes observation dates; a semantic UPDATE must be
positively observed in `pg_blocking_pids`, then finish only after holder release.
The ordinary inner-join view must block the observation UPDATE, proving the
experiment can detect the original coupling. An exclusive authority holder must
deny NOWAIT reads and block an observer's authority SHARE as it should.

For SHARE forms the observation writer first obtains authority SHARE. Under a
view FOR UPDATE, only the direct observation-table write is expected to proceed;
an actual authorizing renewal must still wait for its own authority SHARE. The
probe explicitly tests that distinction. Direct observation date grants exist
only to measure locks and are **not** the recommended production ACL.

Fourteen missing/mismatched/suspended/recovery/incarnation cases check explicit
denial and nonnullable dates. Every reset checks the positive view first. The
probe does not validate production monotonicity, trigger semantics, restore,
initial activation, unknown COMMIT or sustained owner startup. Its synthetic
database activation is explicit fixture setup; it grants no product authority.
Holder/SQL/harness timeouts bound the experiment only, not production deadlines.
No actual captured product deadline is changed or renewed by this proposal.

A pass selects only this view-lock structure for further design review. Any
failure is preserved and must be explained before selecting a migration.
