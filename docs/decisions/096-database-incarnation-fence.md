# ADR-096 — Database incarnation fence before recovery activation

Status: accepted engineering refinement of REQ-DB-005. Initial/restore activation
remains a separate, unfinished protocol. This decision does not authorize it.

## Problem

A PostgreSQL backup can contain `fleet_trust.recovery_blocked=false`. The former
reader trusted that flag once the ordinary fleet observer refreshed configuration.
That lets stored authority become usable without independent recovery acceptance.
The regression reproduces this using the real observer, reader and scoped SQL role.

## Decision

Migration 00031 adds nullable, separately writable activation fields containing
the accepted PostgreSQL server start time and database OID. Neither has a default
or activation backfill. The migration also sets the stored recovery/suspension
flags to blocked under its table lock, fencing already-running legacy readers
that still use the old query. A derived `fleet_current_trust` view reports recovery blocked
when the stored flag is blocked, either activation field is absent/mismatched, or
PostgreSQL is in recovery. All product trust reads, locks and peer joins use that
view. This also reaches final effect checks; a previously obtained recovery proof
cannot override the database's current block.

Ordinary configuration observation can insert a blocked row and refresh its
finite source observation. It cannot write the activation fields, clear recovery,
or replace the epoch. Runtime consumers receive only the view's required SELECT
and installation-column row-lock permissions. The migration owner owns the view;
runtime roles have no DDL or ownership rights. No SECURITY DEFINER function or
new external service is introduced.

PostgreSQL documents [the server start time](https://www.postgresql.org/docs/current/functions-info.html)
and [database OIDs](https://www.postgresql.org/docs/current/catalog-pg-database.html).
These are operational incarnation indicators, not cryptographic attestations or
proof of WAL completeness. [Simple views can mix ordinary writable columns with
read-only expressions](https://www.postgresql.org/docs/current/sql-createview.html),
and [row locks on views apply to their underlying tables](https://www.postgresql.org/docs/current/sql-select.html#SQL-FOR-UPDATE-SHARE).
Real SQL qualification must verify these permissions and locking semantics.

## Failure model and activation

A PostgreSQL restart or a normal physical restore to a new server process changes
the start time. A logical restore into a newly created database changes its OID,
even on the same server. Neither may reuse the saved activation merely because
configuration is current. Application process restarts do not change the database
incarnation and do not independently invalidate otherwise current authority.

Supported restore procedures must stop/fence service and restart PostgreSQL or
create a new database. Arbitrary superuser rewrites inside the same running
database, deliberate clock/identity forgery, or rollback of a complete running
VM/process snapshot are not detected by this fence. A qualified deployment must
control those operations and use independent recovery witnesses. A primary change
still needs old-primary fencing; this view is not a failover controller.

The future activation coordinator must compare protected installation identity,
independently retained revocation/deletion/accounting checkpoints and the current
database, then complete REQ-DB-005's reconciliation before recording activation.
It must distinguish a first installation from restored SQL with missing rows.
It cannot simply copy the current server values or trust SQL's enabled flag.

Lossless restarts should be reactivated automatically once the qualified durability
and fencing checks pass. This decision does not impose a new human approval on
every restart. Uncertain restore history requires the specified invalidation and
conservative spend handling, not an automatic retry that clears the block.

## Scope and rollout

This is C-21 SQL authority enforcement for existing C-04/C-14 consumers. No public
schema, CRD, browser/MCP permission, or artifact format changes. SQLC produces a
distinct effective-trust row type to keep stored flags out of authority helpers.
Migration 00031 preserves history/accounting but intentionally blocks old roots;
fixture-only administrator activation is explicitly synthetic. No production
activation writer exists yet. Reactivation must first fence older processes and
credentials; the legacy query must not survive reopening the stored flag.
Pre-release migration tests do not qualify rolling
N/N-1 production upgrades or highly available database restoration.

Actual verification, source hashes, failures and remaining work are recorded in
[implementation progress](../implementation-progress.md).
