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

Rows are bound to the installation's *activation incarnation*, not to the live server process.
The incarnation lineage is the activation start (`fleet_trust.activated_postmaster_at`) plus every
re-activated lossless restart start, recorded in the append-only table `database_restart`
(update/delete/truncate refused). All of it is defined in migration 00031, so every later check
can use it.

1. Activation also records the cluster's system identifier (`pg_control_system()`) and the
   current WAL timeline (from `pg_walfile_name(pg_current_wal_lsn())`). A trigger (migration
   00080) fills both from PostgreSQL itself when the activation fields are first set and refuses
   any later change, so no caller supplies them and activation writers need no new grant.
2. `public.incarnation_current(x)` (SECURITY DEFINER, owner-only, no runtime EXECUTE) is true
   iff `x` is the live start, or the server is a primary whose live start is in
   `database_restart`, `x` is the activation start or a recorded restart, and the activation's
   database OID, system identifier and timeline equal the live ones.
3. Every per-subsystem incarnation check (connector identity root/profile/process, credential
   attempts, backing transitions, operation-audit lifecycle/history/retirement, context writer
   completion and deletion checkpoints, context queries and their capacity, protected capacity
   pins, capture audit, download stop, evidence read windows) now calls `incarnation_current`
   instead of comparing with `pg_postmaster_start_time()`. Migrations 00039–00077 were edited in
   place; there is no install base to upgrade. `fleet_current_trust` (00031, 00059) inlines the
   same logic because function calls in a view run as the querying role and runtime roles may
   not execute definer functions outside their allowlists. The fleet observer keeps its
   transient live-start parameter check but computes the effective block through the lineage.
4. Operation-audit lifecycles now store the activation start (as Go-written rows already did
   through `ReadContextDatabaseIncarnation`), so Go comparisons with the activation start stay
   valid for lifecycles created after a restart.
5. `reactivate_restarted_database(installation)` (SECURITY DEFINER, EXECUTE for the
   configuration-fleet observer only) appends the live start to `database_restart` only when:
   the server is a primary with `fsync`, `full_page_writes` and a non-`off`
   `synchronous_commit`; the stored flags are unblocked; the database OID, system identifier and
   timeline equal the recorded ones; the accepted observation row still carries the same
   activation; and the live start is later than the activation start. It
   rewrites no activation field and no semantic version. The hub-worker's fleet observation
   calls it before reading each observation basis; an ordinary pass takes no lock.

Processes: hub-api and the publisher detect the database change and exit (fail closed); the
kubelet restarts them and they come back Ready under the re-activated root. native110 measured
re-activation 2 s after the restart; the installed journey waits until every hub process has
been Ready for 20 s before capturing again.

Availability after a restart: re-activation takes about 2 s. The permission reconciler's epoch
fails with the restart and retries after its 30 s SQL controller lease, so authority-dependent
operations are refused for roughly a minute (native117); the installed journey waits until the
permission stream is current again before capturing.

What stays blocked for the separate restore protocol: archive recovery (pgBackRest restore,
point-in-time recovery, promotion), which PostgreSQL ends on a new timeline; a logical restore
into a new database (new OID); another cluster (new system identifier); any server with
weakened durability.

Not detected either: durability is checked only when re-activating. A server that ran with
`fsync=off` or `synchronous_commit=off`, crashed and came back with the settings corrected is
re-activated as lossless. Durable settings are a deployment requirement; a qualified deployment
must not weaken them while serving.

Not detected, as ADR-096 already states for VM snapshots: copying an older data directory back
and starting it as an ordinary restart. Supported restores use pgBackRest.

## Complexity gate

1 every PostgreSQL restart caused a permanent outage; 2 no, ADR-096 asked for this; 3 every
deployment; 4 databases use the timeline/system identifier for the same distinction; 5 one
EXECUTE grant to the existing observer, no new credential; 6 none: re-activation either happens
or the existing block stays; 7 no; 8 PostgreSQL control functions, documented and PUBLIC; 9 one
cheap call per observation pass; 10 migrations edited in place before any install base; activations
without the recorded facts stay blocked; 11 documenting the outage would leave the product unusable
after routine maintenance.
