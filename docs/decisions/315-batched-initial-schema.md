# ADR-315: Batched initial schema brackets

> Superseded in whole or in part by [ADR-330](330-event-driven-system-design.md) (event-driven system design, 2026-11-14). Where this record prescribes polling, expiring freshness windows, per-request Jobs, private PKI or enrollment layers, object-store audit, spent-on-uncertain accounting or installer-era guards, ADR-330 applies.

> Superseded (2026-11-13): The brackets existed to space out protected root
> proofs (administrator, staging-guard and namespace-protection observations)
> during installer DDL. Those proofs are removed. The `setup` hook Job applies
> the embedded migrations forward-only in order under an advisory lock, as
> Goose does, with one transaction per version.

Status: superseded by ADR-328 (administrator-only namespaces); the mechanism is removed by the Helm-native installation plan.
Previously: accepted (agent decision under the maintainer's 2026-10-20 proportionality
rule and the merged [test runtime plan](../reviews/test-runtime-plan-2026-11-08.md),
option 3). Amended the per-step lease of [ADR-130](130-bounded-initial-schema.md).

## Context

The `initial-schema` phase took about 87 s (median) in every installed CI job and
on every real first installation. It ran each of the 146 embedded migrations as
two separate five-second steps, an inspection and an apply, so every migration
paid for:

- five protected root reads (two lease proofs and three `checkRoot`), each a full
  administrator, staging-guard and namespace-protection observation through the
  Kubernetes API (730 reads per installation);
- two new TLS + SCRAM sessions (`SetMaxIdleConns(0)`);
- two database-incarnation checks, four history reads and two table inventories,
  each inventory with one `EXISTS` row probe per existing table (about 19 000
  probes per installation, quadratic in the migration count).

Measured on owned PostgreSQL 18 with a synthetic, cost-free root
(`TestInitialSchemaWithRealPostgres`, race build, 124 migrations after the
first partial run):

| Variant | Time |
| --- | ---: |
| Per-step (before) | 22.8 s |
| Without the per-step row probes | 11.2 s |
| Also reusing the session | 4.9 s |
| Brackets (this ADR) | 2.1 s |

The SQL side is therefore about 23 s of the 87 s; the remaining time is the 730
root observations, about 90 ms each on the CI kind cluster.

The checks protect stated invariants (ADR-098/101/130): exact table inventory
and empty operational rows before completion, bounded locks, one immutable
attempt bound to the original database incarnation and DDL role, the exact
ordered history prefix, and current administrator/guard authority within an
original five-second deadline that a later observation never renews. None of
these requires repeating the observation for every migration: the root,
incarnation and inventory cannot change under the held advisory lock except
through the bracket itself, and each migration is reviewed embedded DDL.

## Decision

`InitialSchema.Run` works in brackets. Each bracket:

1. takes one lease (protected root proof, original five-second deadline), opens
   one session, takes the advisory lock, verifies the original database
   incarnation, DDL role and manager, reads the history, checks the inventory
   including empty operational rows, claims or creates the version table when
   needed, and checks the root again;
2. hands that locked session to Goose through the one-connection pool and applies
   pending versions in order with `ApplyVersion`, each in its own transaction
   with its version row, while at least `initialSchemaStepReserve` (2 s) of the
   lease remains. Before each step the session locker requires the same backend
   PID, the exact preceding history head and a current lease;
3. reclaims the session, requires the same backend PID, rereads the history (head
   equals the last applied version) and checks the root again, then unlocks and
   discards the session, so no lock count or idle session outlives the bracket.

A bracket whose opening checks leave less than the reserve applies nothing and
is retried with a fresh lease, at most three times in a row, then fails at the
`migration-lease-reserve` phase. If the session cannot be reclaimed, idle pool
sessions are closed so no lock lingers. Completion stays a
separate bracket with the unchanged final inventory, grants and root
completion. One run now needs about two brackets (six root reads) instead of
730 reads.

Preserved: the protected root and claim record, the original five-second
deadline of every bracket (a closing or narrower observation still shortens it,
never extends it), one transaction per migration with its version row, the
exact ordered prefix and resume after an uncertain commit, the advisory lock and
no takeover, the original incarnation/role/manager binding, the exact final
inventory with empty operational rows, the closed Goose store (no create/delete,
no down migration), and stopping on any uncertain reply.

Dropped: the root proof, incarnation check and inventory between individual
migrations of one bracket. A revoked administrator or changed guard is now
noticed at the bracket's closing root check, at most one lease (five seconds)
later, instead of before the next migration. The work done in that window is
the embedded reviewed DDL that the original proof already authorized, and the
next bracket or completion still fails closed. Rows written into operational
tables mid-bracket are still rejected by the next bracket and by completion.

`UpgradeSchema` (ADR-227) is unchanged: it has no root proof and already holds
no per-step authority reads.

## Complexity checklist

1. Problem: every installation and every installed CI job (36 per full
   dispatch), about 87 s each; not hypothetical.
2. Maintainer-accepted risk: none reopened; the five-second authority window and
   the protected root are kept.
3. Typical deployments: yes, every first installation.
4. Precedent: Goose `Up`, Flyway and Liquibase apply all pending migrations under
   one lock acquisition; this keeps Goose's per-version transactions.
5. Privileges, credentials, network access: none added.
6. New failure states: one (a bracket without time for a migration), retried
   up to three times and then failing like any other unavailable step.
7. Configuration: none; the reserve is a constant.
8. External dependencies: none new; relies on PostgreSQL session advisory locks
   and `pg_backend_pid`, both already used or standard.
9. Cost: Kubernetes reads per installation fall from about 730 to about 6, SQL
   sessions from about 300 to about 3, catalog row probes from about 19 000 to
   a few hundred.
10. Upgrades and rollback: the persisted root record, history table and
    migrations are unchanged, so a run interrupted by an older binary resumes
    with the new one and vice versa; the incremental upgrade path is unchanged
    and tested by `TestCustodyUpgradeSchemaWithRealPostgres`.
11. Smaller fix: dropping only the row probes and reconnects saves about 18 s;
    the root reads are the larger share, so the bracket is the smallest change
    that removes both.

A squashed fresh-install baseline was rejected: it would change the bundle digest
and history shape that the completed root binds and the upgrade floor reads, add
a second migration source to keep equivalent, and still leave the per-step
proofs for incremental runs.

## Qualification

`TestInitialSchemaWithRealPostgres` now stops a first bracket early through a
short root lease, loses its closing proof, requires an exact partial prefix with
the failure at that version, resumes after one bracket opened below the reserve,
and fails if the resume
needs as many root reads as migrations. Installed timings are recorded in
[implementation progress](../implementation-progress.md).
