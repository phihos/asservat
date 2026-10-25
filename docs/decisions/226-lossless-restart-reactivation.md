# ADR-226 — Automatic re-activation after a lossless PostgreSQL restart

Date: 2026-10-25. Status: implemented; real SQL qualified, installed qualification pending.
Refines [ADR-096](096-database-incarnation-fence.md), which required that "lossless restarts
should be reactivated automatically once the qualified durability and fencing checks pass"
but left the writer unimplemented.

## Problem

`fleet_current_trust` reports recovery blocked whenever the recorded server start time differs
from `pg_postmaster_start_time()`. Only the first installation writes activation. Any PostgreSQL
restart (node drain, upgrade, crash) therefore blocked every capture, download and enrollment
permanently. The database-recovery test hid this with a fixture-only SQL update.

## Decision

1. Activation also records the cluster's system identifier (`pg_control_system()`) and the
   current WAL timeline (from `pg_walfile_name(pg_current_wal_lsn())`). A trigger fills both
   from PostgreSQL itself when the activation fields are first set and refuses any later change,
   so no caller supplies them and activation writers need no new grant (migration 00080).
2. `reactivate_restarted_database(installation)` (SECURITY DEFINER, owned by the migration
   owner, EXECUTE for the configuration-fleet observer only) re-records the start time in
   `fleet_trust` and `fleet_observation` only when: the server is a primary with `fsync`,
   `full_page_writes` and a non-`off` `synchronous_commit`; the stored flags are unblocked; the
   database OID, system identifier and timeline equal the recorded ones; and the new start is
   later than the recorded one. The guard trigger advances the semantic version, so proofs from
   before the restart stay unusable.
3. The hub-worker's fleet observation calls it before reading each observation basis. An
   ordinary pass takes no lock.

Processes: hub-api and the publisher detect the database change and exit (fail closed); the
kubelet restarts them and they come back Ready under the re-activated root. native110 measured
re-activation 2 s after the restart; the installed journey waits until every hub process has
been Ready for 20 s before capturing again.

What stays blocked for the separate restore protocol: archive recovery (pgBackRest restore,
point-in-time recovery, promotion), which PostgreSQL ends on a new timeline; a logical restore
into a new database (new OID); another cluster (new system identifier); any server with
weakened durability.

Not detected, as ADR-096 already states for VM snapshots: copying an older data directory back
and starting it as an ordinary restart. Supported restores use pgBackRest.

## Complexity gate

1 every PostgreSQL restart caused a permanent outage; 2 no, ADR-096 asked for this; 3 every
deployment; 4 databases use the timeline/system identifier for the same distinction; 5 one
EXECUTE grant to the existing observer, no new credential; 6 none: re-activation either happens
or the existing block stays; 7 no; 8 PostgreSQL control functions, documented and PUBLIC; 9 one
cheap call per observation pass; 10 additive migration, old activations without the new
columns stay blocked as before; 11 documenting the outage would leave the product unusable
after routine maintenance.
