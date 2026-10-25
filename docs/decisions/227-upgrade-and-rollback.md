# ADR-227 — Supported upgrade and image-only rollback

Date: 2026-10-25. Status: accepted (maintainer chose to build the upgrade path now); phase 1 in
progress. Implements the upgrade target in [operations](../operations.md#backup-recovery-and-upgrades)
and [persistence](../../specs/persistence.md) (N/N-1, separate DDL role, expand/contract).

## Problem

An installation cannot be upgraded. Migrations run only at first installation (InitialSchema
refuses a non-empty database), about a dozen runtime constructors require the database schema to
equal the binary's compiled version exactly, and the release image is pinned independently in about
eight places (bootstrap seed digest, preparer plan, runtime-resources journal, hub-worker and owner
launch digests, federation/key-service/publisher input stamps, download-worker profile, regional
offer). Several of those are immutable, and none may be rewritten.

## Decision

1. **Schema compatibility from the database, not a window guessed by the binary.** Migration 81
   adds `schema_compatibility(oldest_binary_schema)`. An expand migration leaves it unchanged; a
   contract migration (one that removes or reinterprets something an older binary uses) raises it to
   its own version. A binary with compiled head `H` runs against a database with head `D` and floor
   `F` when `D >= H` (everything it needs exists) and `F <= H` (nothing it needs was removed). So an
   N+1 database runs both the N and the N+1 binary after an expand migration, which is image-only
   rollback; an N database refuses the N+1 binary until migrated. Every exact `== currentSchemaVersion`
   check uses this rule.
2. **Upgrade migrator.** A new one-shot `installer-upgrade` command, run by the installer's existing
   runner account with the operator's DDL credential (the DDL role keeps its login and owns the
   schema; [initial schema](../architecture/initial-schema.md)). It requires the completed
   installation root, verifies the applied history is an exact prefix of its embedded migrations with
   nothing foreign, and applies the rest with the same advisory lock and step checks as
   InitialSchema. It never edits the completed InitialSchema record. Phase 1 migrations add no runtime
   grants, so the role layout digests and existing role receipts stay valid; grant changes need role
   re-production (later phase).
3. **One release record (simplification).** One installation release record, a ConfigMap
   `asservat-release-<installation>` in the hub namespace (it holds no secret data), written only by
   the installer runner account (the sole principal the hub workload guard admits) with
   resourceVersion preconditions. It holds the original revision-1 image, the current and previous
   image, the target schema, the workload generations and a bounded history, with a monotonic
   revision. Verifiers read it inside the existing guard bracket and map a live image that the record
   names (current or previous) back to the original image before their existing checks, so the
   immutable install-time digests (binding, owner deployment input, regional offer, running/inert
   digests) stay valid unchanged. An upgrade writes the next revision after the migrator succeeded
   and then updates the hub-worker and hub-api Deployments' images; a rollback names an image from
   the history and is allowed only while the schema floor permits that image's schema. Fresh
   installations only: the hub Roles gain read access to the record.
4. **No downgrade of the schema.** Rollback is image-only. A database migrated past an older
   binary's floor stays on the newer image; operators restore from backup instead.

## Phases

1. Schema compatibility rule and `installer-upgrade` migrator, qualified against a real database:
   install at N, apply an additive N+1 migration, run N and N+1 runtime constructors against it.
2. Release record and verifier switch for the hub workloads; upgrade and rollback of hub-api and
   hub-worker images in the installed journey.
3. Federation, key service, publisher, download workers and the regional connector on the same
   record; chart `post-upgrade` hook.

## Complexity gate

1 every installation needs upgrades from its first release; 2 no: the maintainer asked for it now;
3 typical; 4 expand/contract with a minimum-compatible version is how comparable systems migrate;
5 no new credential: the existing DDL credential and runner account; 6 one new state (release
revision), and migration failure leaves the previous release running; 7 no new configuration;
8 no; 9 one Secret read per verifier, cached as the pins were; 10 upgrade and image-only rollback
are the point and are tested; 11 not doing it leaves every release requiring reinstallation, and the
release record replaces eight independent pins, so the design removes more than it adds.
