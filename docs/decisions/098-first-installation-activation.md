# ADR-098 — Audited first-installation activation

Status: accepted engineering refinement of REQ-DEP-005 and REQ-DB-005.
Implementation and qualification are tracked in [progress](../implementation-progress.md).
This is first installation only; restart/restore activation remains separate.

## Decision

Add one immutable SQL attempt per dedicated installation database under migration
00032. Preparation binds the ADR-097 witness scope, current protected fleet-source
revision, installation plan digest, actual PostgreSQL process/database/schema and
a five-minute deadline. Only an unused witness may create the first SQL attempt.
A consumed witness with missing SQL cannot recreate it. Exact retries keep the
original claim and deadline; there is no reset/refund operation.

Before preparation and first activation, verify the exact permanent-table
inventory and lock all application tables. Allow only migration history, the
exact pending installation attempt and an optional matching, never-activated
blocked fleet root. Any operational row, foreign root, missing/unknown table,
row-security policy or prior activation rejects first installation. Repeat this
check in the final transaction so state appearing during provider I/O cannot be
mistaken for a pristine installation. Require a dedicated database and fenced
migrations; this is not a concurrent schema-upgrade protocol.

PostgreSQL [table locks](https://www.postgresql.org/docs/current/sql-lock.html)
can stabilize all relevant rows under READ COMMITTED. SHARE ROW EXCLUSIVE also
serializes competing installers. SELECT alone is insufficient for that lock;
the temporary preparation/activation roles use table-scoped MAINTAIN and SELECT.
[MAINTAIN](https://www.postgresql.org/docs/current/ddl-priv.html) also permits
maintenance operations, so these are trusted, short-lived installation roles,
never ordinary service credentials. No operational-table DELETE, TRUNCATE or
UPDATE grant or SECURITY DEFINER function is needed. All original observation
deadlines remain binding after lock waits. SQL transaction timeouts and enabled
synchronous_commit do not by themselves qualify failover durability.

The coordinator consumes the protected Kubernetes witness before provider work,
writes a purpose-separated encrypted initial-attempt audit, independently reads
and verifies it, and records its receipt through a separate audit credential.
It then refreshes witness/source observations without replacing their identities,
revision or attempt deadline. Activation atomically records the accepted database
incarnation, enables that exact initial fleet root and marks the attempt complete.
No key-service operation depends on ordinary evidence authority already being
active: protected installation supplies dedicated audit key/store credentials.
The installer must revoke those credentials after completion.

A lost COMMIT reply permits exact result lookup. A completed attempt can never
clear a later suspension/recovery block, renew the source, change the database
incarnation or activate a replacement installation. Expired or inconsistent
attempts require recovery. The immutable audit records an attempt; only the SQL
transaction establishes its activation result. There is no public recovery API,
developer approval step, new dependency or chart runtime enablement.

## Boundaries

C-04 owns preparation/activation ports and coordinator, C-08 owns the encrypted
audit contract and acknowledgement, and C-21 implements PostgreSQL/S3 adapters.
The private audit uses existing envelope encryption; no payload goes to a transit
service. Its exact scope/claim is minimized control data. Production installer
provisioning must retain pins, prevent witness replacement, protect credentials,
pin the plan and retire temporary roles. Constructors are not attestations.

The implementation does not qualify a deployed installer, independent historical
checkpoints, old-primary fencing, restored grants/accounting reconciliation or
automatic lossless-restart activation. Those remain mandatory before the full
platform is operational. The [component contract](../architecture/initial-installation.md)
and progress record distinguish synthetic inputs from actual provider evidence.
