# ADR-227 — Supported upgrade and image-only rollback

Date: 2026-10-25. Status: accepted (maintainer chose to build the upgrade path now); phases 1
and 2 implemented; phase 3 implemented for the key service, publisher and federation (download workers, regional connector and the chart hook deliberately not built). Implements the upgrade target in [operations](../operations.md#backup-recovery-and-upgrades)
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

## Phase 3 (implemented, with deliberate omissions)

- **Followers: key service, publisher, federation.** These three hub-namespace Deployments
  are the remaining SQL users. Nothing checks their image or generation while they run: no
  runtime reader looks up their Deployments, Pods or ReplicaSets. Callers authenticate them by
  mTLS and service-account identity, and a continuation replay compares only the
  template-digest annotation, which an image change leaves alone. So they follow the record
  without any mapping, generation pins, record format change, Role rule or API read in a runtime
  process. `installer-upgrade` reads each one (`kube.ReleaseFollowerNames`; one is skipped
  when the installation did not enable it), requires that it runs the original image or one
  in the record's history, and then, after hub-worker and hub-api, changes the image of each
  one not yet on the target: key service, then publisher, then federation. The settle wait (5
  minutes, unchanged for 20 s) now covers all present Deployments. A follower on an image the
  record does not name is refused before anything changes. A settled record whose follower runs
  another image is refused too. A follower left on the original image by a phase-2 runner is
  rolled forward by the next run. A rollback to a phase-2 image leaves the followers on the
  newer image, because the phase-2 runner does not know them. Those followers still run against
  the database: a rollback does not lower the head, and the floor admits the rollback target.
  The next phase-3 run moves them. All three use the Recreate strategy, so each is briefly
  unavailable during its rollout. With every SQL user now following the record, the phase-2
  guard (a migration may not raise the floor past `history[0].schema`) keeps every runnable
  release and every running process in range.
- **Download workers: not built (gate failed).** They run the profile image, which is pinned
  in the audited SQL worker configuration revision, the hub-api's download path template (its
  revision UID, generation and digest), the key service's immutable input and every Job/Pod spec
  digest. Dispatch and attestation compare those digests exactly. Following the record would
  mean a per-intent image in SQL (a custody migration) and record mapping inside worker
  attestation, an authorization path, for a process that lives at most an hour. Benefit is weak
  (fixes in the download-worker code only), cost is real (schema, attestation, two more
  readers). They stay on the original image. The download worker opens no SQL connection, so
  the schema floor does not constrain it. A release must stay wire-compatible with the original
  worker toward hub-api and the key service.
- **Regional connector: not built (gate failed).** It runs on workload clusters that cannot
  read the hub-namespace record. Its image comes from the hub-signed regional offer, which is
  digest-bound and immutable, and is checked as `OwnerPublicExecutor.ImageDigest`. Following
  the record would need a new upgrade flow per workload cluster, a changeable signed image
  carrier and hub-side mapping for connector callers. It would also need a rollback order across
  clusters against one hub history. That is several new failure states across trust domains.
  It stays on the original image. The connector also opens no SQL connection; releases must
  keep the federation and hub-api protocols compatible with the original connector.
- **Chart `post-upgrade` hook: not applicable.** The chart renders no runtime workload
  (`runtime.enabled: true` is rejected). Every runtime Deployment is created by the product
  installer inside the existing bootstrap hook Pod, and its `post-upgrade` run replays that
  installer, not a release change. A Helm hook would only wrap the same `installer-upgrade`
  Pod. The operator runs `installer-upgrade` explicitly (runner account, DDL credential, Pod of
  the target image).
- **Role re-production: not needed yet.** No pending migration adds a runtime grant: head is
  00081, which only sets the floor comment. A future migration that adds grants must add role
  re-production with it; until then the migrator applies only grant-free migrations
  (limitation).

## Complexity gate

1 every installation needs upgrades from its first release; 2 no: the maintainer asked for it now;
3 typical; 4 expand/contract with a minimum-compatible version is how comparable systems migrate;
5 no new credential: the existing DDL credential and runner account; 6 one new state (release
revision), and migration failure leaves the previous release running; 7 no new configuration;
8 no; 9 one ConfigMap GET per hub workload check (measured: one per native boundary, e.g. 40 to 42 reads for a configuration-provider operation pair); 10 upgrade and image-only rollback
are the point and are tested; 11 not doing it leaves every release requiring reinstallation, and the
release record replaces eight independent pins, so the design removes more than it adds.

Phase 3, per component (questions 1–11):

- *Key service, publisher, federation (built):* 1 every release fix in them was otherwise
  unreachable without reinstallation, and after 16 revisions the original drops out of the
  history, so the floor guard no longer protects them; 2 no; 3 typical (the publisher and key
  service exist whenever downloads are enabled; the federation whenever a regional cluster is);
  4 rolling a Deployment's image is the standard mechanism; 5 none: the runner already holds
  Deployment get/update; 6 no new state, the existing resume rule covers them; 7 no; 8 no;
  9 runtime cost zero; `installer-upgrade` does up to 3 more GETs at the start, 3 GET+PUT in
  the rollout and 3 more GETs per 2 s settle poll; 10 the same upgrade/rollback, tested natively;
  11 doing nothing leaves SQL users on a schema the floor guard stops protecting.
- *Download workers (not built):* 1 weak: a process of at most one hour with no SQL access;
  4 –; 5–6 a per-intent image in SQL plus record mapping in worker attestation, an
  authorization path; 9 a record read per dispatch and per attestation; 11 the documented
  wire-compatibility limitation is enough.
- *Regional connector (not built):* 1 moderate, but it opens no SQL connection; 3 every regional
  cluster; 5 a new carrier, or new read access across the cluster boundary; 6 per-cluster partial states and
  cross-cluster rollback ordering; 8 depends on operator runs in each workload cluster;
  11 the documented limitation is enough until a connector fix requires a change.
- *Chart hook (not applicable):* the chart deploys no runtime workload.

Phase 3 verification: the installed `ASSERVAT_JOURNEY_FOCUS=upgrade` run passed in 745 s. It
requires the key service, publisher and federation to be settled on the target image after both
the upgrade (24 s) and the rollback (26 s). The capture, publication and download after the
upgrade ran with the upgraded publisher, key service and federation, the original download
worker and the original connector. The restart focus still passes (735 s).
