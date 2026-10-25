# ADR-227 — Supported upgrade and image-only rollback

Date: 2026-10-25. Status: accepted (maintainer chose to build the upgrade path now); phases 1
and 2 implemented, phase 3 pending. Implements the upgrade target in [operations](../operations.md#backup-recovery-and-upgrades)
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
   records the floor, the oldest binary schema the database still serves, as the comment of the
   migration version table (`asservat:oldest-binary-schema=N`). Only the schema owner can set a
   table comment, and every role reads it through `obj_description` without a grant, so no runtime
   grant or role layout changes. (The version table is created by the migration runner, so the
   migration sets the comment in a `DO` block the SQL code generator does not resolve.) An expand
   migration leaves the floor; a contract migration (one that removes or reinterprets something an
   older binary uses) raises it to its own version. A binary with compiled head `H` runs against a
   database with head `D` and floor `F` when `D >= H` (everything it needs exists) and `F <= H`
   (nothing it needs was removed); without a recorded floor `D` must equal `H`. So an N+1 database
   runs both the N and the N+1 binary after an expand migration, which is image-only rollback; an N
   database refuses the N+1 binary until migrated. Refusals name their reason (older, newer than
   tolerated, unreadable).
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

## Phase 2 (implemented)

- **Record.** `asservat-release-<installation without dashes>`, key `state.json`, format
  `asservat-release/v1` (`internal/contracts/release_record.go`): installation, revision,
  original, image, previous, schema, per-Deployment `launch`/`generation`/`previousGeneration`
  and at most 16 history entries. Decoding is strict and canonical; validation requires a
  contiguous history ending at the current image, `generation = launch + revision - 1` and the
  previous image's generation one lower. The ConfigMap must carry no labels, annotations,
  owners, finalizers or binary data. `installer-continue` creates revision 1 right after the
  runtime resources step (create-only; a replay accepts exactly that revision 1, or a later
  revision with the same installation and original image). The hub-api and hub-worker Roles
  gain `get` on that one name (fresh installations only).
- **Mapping.** `releaseOriginal` (`internal/adapters/kubernetes/release_record.go`) accepts a
  hub Deployment whose image is the record's current image at that workload's `generation`, or
  its previous image at `previousGeneration`, and returns a copy with the original image, the
  launch generation and revision annotation `1`; ReplicaSet and Pod images map the same way and
  any other image maps to none. Without a record, or at revision 1, nothing is mapped. The
  existing checks then run unchanged on the copy. Runtime sites routed through it: the hub-api's
  own Deployment check (`InstalledOwnerIdentityReader.deployment`), the cluster-observation caller
  check for a hub caller (`liveObjects`; connector callers pass no record), the hub-worker's
  owner-operation check (`validateObjects`, record read right after the guard proof) and the
  hub-worker's own Deployment and process checks (`checkedWorkerDeployment`,
  `configurationProviderProcessDeployment`). The install-time-only sites (continuation steps,
  `configuration-role-install`) run at revision 1 and are unchanged. Install-time digests
  (binding, owner `deployment.json` observation and caller pins, regional offer, running/inert
  digests) are unchanged.
- **Change.** `installer-upgrade --inputs dir --image repo@sha256:… --namespace hub
  --installation id`, run as the installer runner in a Pod of that image (the command reads its
  own Pod through the downward API name and requires that image). It reads the record and both
  Deployments (each must run a recorded image), then either upgrades (image not in history:
  refuse when the migrations' declared floor exceeds `history[0].schema`, run the migrator,
  require `head >= compiled` and `floor <= compiled`) or rolls back (image in history: refuse with
  "restore from backup" when the database floor exceeds that entry's schema; no migration). It
  writes revision N+1 (UPDATE at the read resourceVersion), updates hub-worker then hub-api
  (image only, resourceVersion precondition, the resulting generation must be the recorded one),
  waits up to 5 minutes for both to settle and writes the same revision with `previous` empty.
  A failure before the record update changes nothing; after it both images verify and a rerun
  with the same image resumes; another image is refused until then. The runner does not prove the
  workload guard itself; every runtime reader still does.

Remaining for phase 3: federation, key service, publisher, download workers and the regional
connector on the record (they stay on the original image); a chart `post-upgrade` hook;
role re-production for migrations that add grants.

## Complexity gate

1 every installation needs upgrades from its first release; 2 no: the maintainer asked for it now;
3 typical; 4 expand/contract with a minimum-compatible version is how comparable systems migrate;
5 no new credential: the existing DDL credential and runner account; 6 one new state (release
revision), and migration failure leaves the previous release running; 7 no new configuration;
8 no; 9 one ConfigMap GET per hub workload check (measured: one per native boundary, e.g. 40 to 42 reads for a configuration-provider operation pair); 10 upgrade and image-only rollback
are the point and are tested; 11 not doing it leaves every release requiring reinstallation, and the
release record replaces eight independent pins, so the design removes more than it adds.
