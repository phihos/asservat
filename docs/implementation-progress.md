# Sustained implementation progress

## Recovery proof removed (2026-11-15)

Branch `clean/recovery-2`. Migration 00173 removes
`fleet_current_trust.recovery_blocked` from the view and from every stored
function body; its Down restores the 00167 view for downgrade probes.
`RecoveryProof`, `RecoveryState`, every `RecoveryReader`,
`RecoveryTransactionGuard` and `EffectTransactionGuards` are gone from domain,
application, adapters, bootstrap and transport; effect transactions no longer
lock or check the trust row for recovery. `currentTrust` refuses a suspended
or stale trust row. Open: the setup recovery step of REQ-DB-005;
retention topology, proofs and source checkpoints (D12); one-step publication;
the unused `identity-read` pools that only served recovery reads.

## Standing connector identity (ADR-332, 2026-11-14)

Branch `fix/connector-backing-expiry`. Homelab defect: after the offer's
connector backing `ValidUntil` (first hub-api start + `validSeconds`) no
connector restarted (`startup connector: waiting at identity`). Reproduced
on owned kind `asservat-bk` (repro build accepting `validSeconds: 120`): the
Pod deleted after `ValidUntil` never enrolled. Fix: the backing is standing
(9999-12-31T23:59:59Z), `federation.connector.{validSeconds,accounts,
recordsPerAccount,profiles,sourceTransitions}` are removed, and migration
00164 drops the ticket-admission/purge bound, the retained-process and
serving-slot counts and the identity-lane record/account/profile/transition
caps. hub-api retries a not-yet-current owner configuration in-process.
Fresh kind install of the fix (`retainedSeconds: 2200`): ten connector Pod
deletions in a row, three minutes after hub-api start, each enrolled in
1.7–2.1 s (11 serving processes, identity `charged` 33);
`TestHelmNativeKindJourney` passed (21.9 s) afterwards; a plain
`helm upgrade` left hub-api at 0 restarts (`startup hub-api: ok after 5
failed attempts` during the 15.5 s hub-worker Lease wait) and the next
connector restart enrolled in 2.7 s. Real PostgreSQL:
`scripts/test-custody.py --run
'^TestContextAdmissionWithRealServices$/^connector-(trial-profile|identity-fast|retirement-prepaid-fast)$'`
passed, including a restart beside eight earlier serving processes with a
full record count and a later cluster staging its profile past the root's
structural sizes. Not verified: a late `clusters:` join on the kind hub
issued no join Secret (`remote cluster join eu: not-issued: credential/other`,
then `reserve/other` after a hub-api restart) — an ADR-331 bootstrap
issuance problem outside these limits, still open; no second workload
cluster was installed. Older installations keep their finite stored
backing and must be reinstalled.

## Capacity accounts (2026-11-15)

Branch `clean/capacity-2`, migration 00172. Capacity is on in every hub
(ADR-335 D1). The hub-worker applies the Helm `capacity` values once at
start (`capacity_apply`); a workload's account is created on demand in the
storage read that first needs it (`capacity_enroll`, hub-metadata-read
login). Rows carry the standing date `capacity_standing()` instead of a
renewed admission window. Charges grow an account's limit as burst within
its hard limit, the namespace limit and the pool, and release shrinks it
back to the protected share. Removed: migration 00054's source, plan,
renewal and refresh-demand tables and loops, connector capacity delivery,
cluster-observation capacity purposes, the context-control record counter
and the download session/response counters (bytes stay bounded).
`capturesPerCluster` defaults to max(8, node count).

Gaps: the default share divides by max(8, enrolled accounts), not the
eligible-workload count; namespace eligibility (system/release namespaces,
`asservat.io/evidence: disabled`) is not checked on enrollment because the
storage read knows only the namespace UID; `maxConcurrentExpensive` and
`onFull` are stored but no expensive-action reservation consumes them yet;
`DeleteOldestEligibleInAccount` has no deletion path.

## Capacity from Helm values (2026-11-14)

Branch `clean/capacity`. The `capacity` values follow
`specs/contracts/capacity.schema.json` (now in the chart schema). The
hub-worker derives one pool and one policy per cluster from them and the
release revision; audit lanes, footprints and the backup profile are
internal. Namespaces take part unless they are system namespaces, the
release namespace or labelled `asservat.io/evidence: disabled`.
`capturesPerCluster` (default 8) and `workload.dump` (burst 1, 900 s) reach
the hub-api. Removed: EvidenceStoragePool/EvidenceBudgetPolicy and
CapacityReservation CRDs with their decoders, guards and gates; the
lifetime `max_captures` counter (migration 00165); the 16-capture and
active-policy caps; per-policy cooldown/burst ceilings. Migration 00166
lets `bestEffort` storage enroll.

Verified: unit tests of the changed packages, `make helm-check`, the CI gate
set, `TestCapacityValuesSourceWithRealPostgres` (real PostgreSQL). Gaps: the
default share divides by max(8, clusters + 1), not the eligible-workload
count; the
`capturesPerCluster` default ignores node count; `maxConcurrentExpensive`
and `onFull` are not enforced; capacity is on only when a value is set; the
SQL capacity subsystem (00054, object counts, five-second observation
loops) is unchanged.

## Public API cleanup, first pass (2026-11-14)

Removed `get_live_capacity` with its regional live-runtime query, viewer
count adapter and console page (live load is Prometheus metrics). Capture
progress revisions notify over PostgreSQL (`asservat_capture_progress`,
migration 00168); the console follows `GET /api/v1/events?capture_id=` and
`get_capture` no longer returns poll advice. Remaining divergence is in the
tables below.

## Connector ServiceAccount tokens (ADR-334, 2026-11-14)

Branch `clean/connector`. Connectors authenticate every lifecycle
conversation with their projected ServiceAccount token (`hub.token`,
audience: the federation URL they dial). The federation verifies it against
the hub cluster's API server issuer (combined mode) or each registered
cluster's `issuer`/`jwks` from the `clusters` values (go-oidc; discovered
keys refresh on an unknown `kid`) and attributes the conversation to that
cluster; `revoked: true` or removal refuses its tokens. A cluster's first
conversation stages its connector source. Removed: one-use bootstrap
records, their audited issuance, reservations and KV channel
(`fleet-bootstrap` mount, provider role), `<name>-region-bootstrap`, the
join Secret's record, the rotating cluster credential (lineage, rotation
endpoint, `<name>-cluster-credential` Secret), enrollment claim/certificate
tables (migration 00169) and the 15-cluster cap. Fresh all-bundled
combined install on the owned kind cluster `asservat-cn` (since deleted):
the connector enrolled with its token (no `region-bootstrap` or
`cluster-credential` Secret exists) and `TestHelmNativeKindJourney` passed
(19.7 s; 17.6 s again after rebasing on main). Not run: `TestHelmNativeKindClusterJoin` (mode=cluster).

Remaining for this slice: see "Connector token transport" below.

## Connector token transport (ADR-334, 2026-11-15)

Branch `clean/connector-2`. Context starts (hub-api native port) and
key-service wraps authenticate connectors by their ServiceAccount bearer token,
verified like the federation's (`contracts.ConnectorTokens`, rendered once by
`asservat.connectorTokens`); the hello must name the token's cluster and peer.
The hub keeps its owner certificate; the connector process has a random epoch
and no certificate. Removed: connector process credentials, enrollment,
renewal, registration and retirement (Go side), the connector PKI mount and
roles, the federation's audit/OpenBao/object-store credentials and three SQL
duty logins, the source frames of the context-start stream, the connector
observation/operation channels and the hub's ADR-197 operation port, owner
relay and forwarding, the native forwarded path and the owner-path native
handler, process self-proofs (`ConnectorAPIExecutionProtection`), and
`fleet_peer`/`fleet_peer_certificate` (migration 00171). The connector now
announces `query/resolve-source-snapshots`, which hubs refused before.

Migration 00174 drops the connector identity SQL lane of migrations
00049/00051/00164 (`connector_identity_*`, `connector_credential_attempt`,
retirement tickets, `connector_operation_*` views, the `identity` audit lane)
after rewriting the shared operation-audit functions without it. 00154 and 00164 skip their connector
statements once the lane is gone, so downgrade probes still work.

The unused `federation` values (the regional offer's connector limits) are
removed. Gaps: the join Secret still carries the offer and copied
object-store capabilities; cluster IDs still come from values; `hub.url`/
`hub.caBundle` are not implemented; work JWS and local-key signing rows below
are unchanged; the node channel is in "Node channel stream" below.

## Node channel stream (ADR-330 D2/D3, 2026-11-15)

Branch `clean/connector-3a-node`. The collector holds one HTTP/2 stream to its
connector (`/internal/v1/node/connect`), presents its projected token
(TokenReview once per connection, 50/s burst 200, 429 with `Retry-After`),
sends Hello (version, work kinds) and pushes status on change; the connector
pushes work and sends only announced kinds. Uploads go on the same connection.
Removed: node issuer and client certificates, enrollment and its limiter,
long-poll, status cadence and spacing, renewal, the collector's boot-ID read
and epoch, Pod/DaemonSet attestation reads and RBAC, and node-side checks of
work bindings against its own identity. Gap: work bindings still carry
`bootID`/`collectorEpoch` as hub provenance (SQL, manifests, `internal-work`);
the connector fills them from the Node object and a per-collector-Pod
generation.

## Fleet settings removed (ADR-335 D14, 2026-11-15)

Branch `clean/connector-3a-fleet`. The access and retention previews and share
administration check `identity.administrators` from the identity settings
the hub-api already reads (added to the implemented identity-settings copy and
the chart). Removed: the fleet ConfigMap, `fleet` chart values, its schema and
reader, the fleet protection guard, `contracts.FleetSettings`, the setup Job's
Kubernetes RBAC, and the unreachable configuration-role/installer chain that
depended on the reader. The SQL `fleet_trust` row and its observer stay: about
45 migration functions require a fresh row. Its observation now comes from the
generated installation ID and issuer epoch alone.

Gaps: the fleet trust heartbeat (one SQL observation per second) remains until those
functions stop checking `fresh_until`; `administrators` is optional in the
implemented identity copy until the identity reader adopts the canonical
contract; the `fleet-operator` role name stays in docs/interfaces.

## ADR-330 contract divergence (2026-11-14)

The canonical contracts in `specs/contracts/` and `docs/interfaces/` follow
ADR-330. The runtime still implements the earlier versions, which are kept
byte-for-byte under `specs/contracts/implemented/` and `examples/implemented/`.
Runtime consumers read through them: the embedded Go schema bundles
(`scripts/manifest-schemas.py`, `scripts/investigation-schemas.py`), the
generated CRDs (`scripts/policy-crd.py`), the
console contract generator (`web/scripts/contracts.mjs`) and the Go/console
tests that load contracts or examples. Spec gates validate only the canonical
files. Delete an `implemented/` file in the change that makes its runtime
implement the canonical contract.

| Contract | Canonical change | Runtime still implements (code) |
| --- | --- | --- |
| `mcp-tools.json`, `browser-openapi.yaml` | Stateless previews: `plan_digest` out, `preview` + `expected_plan_digest` + `idempotency_key` in; `resolve_capture_request` and `continue_acquisition` removed | Stored preview handles, resolution tool and continue flag: `internal/transport/presentation/context_operations.go`, `recording_save_operations.go`, `recorder_preview.go`; `internal/domain/audit/operation.go`; `internal/bootstrap/public_context.go`; console `web/src/capture`, `web/src/recordings` |
| `mcp-tools.json`, `browser-openapi.yaml` | Pending results carry `revision`; `get_capture`/`get_grant`/`get_query_result`/`get_artifact_download` take `after_revision` and wait ≤30 s; `get_capture` has no poll advice | No `after_revision` wait (the request-scoped identity and audit windows end after 5–20 s); query results keep `retry_after_seconds`: `internal/transport/presentation/context_projection_operations.go` |
| `browser-openapi.yaml` | SSE: `GET /api/v1/events` (`StatusEvent`), `GET /api/v1/live/watches/{watch_id}/events` (`live-watch.schema.json#/$defs/event`) | `/api/v1/events` serves `capture_id` only (`internal/transport/browser/events.go`); grant, download and query events and the live-watch stream are missing; console still polls queries and live watches |
| `mcp-tools.json` | `get_grant`/`list_reviews`/`request_policy_grant` drop `preview_id`, `can_resolve`, `resume_requires_original_client` | `internal/application/authorization/grants.go`, `internal/transport/presentation/grant_operations.go` |
| `mcp-tools.json` | `explain_access`/`preview_access_change`: `ClusterNotObserved` replaces `PermissionObservationStale`; no `valid_until` | `internal/domain/authorization/explain.go`, `internal/transport/presentation/access_preview_operations.go` |
| `live-watch.schema.json`, `read_live_watch` | `wait_ms` ≤30000; no `retry_after_ms`, `row_max_age_seconds`, `managed_row_max_age_seconds`, source `handle_expires_at`; row expiry is min(privacy, watch deadline) | `internal/domain/live/watch.go`, `internal/domain/live/source.go`, `internal/application/live/service.go` |
| `recording-save.schema.json` | Preview has `plan_digest` instead of `preview_id`/`capture_id`/`expires_at`/`save_scope_digest`; no recording `handle_expires_at` | `internal/transport/presentation/recording_save_operations.go`, `internal/domain/live/source.go` |
| `capture-assessment.schema.json` | No `validUntil` | `internal/application/planning/context_assessment.go`, `recorder_assessment.go` |
| `packet-capture.schema.json` | No `peers.maxStaleness` (peers follow watch events) | `internal/application/planning/peers.go`, `recorder.go`, builtin profiles `internal/application/planning/profiles/*.json`, `internal/bootstrap/regional_peer_verifier.go`; DebugPolicy/CaptureProfile CRDs |
| `browser-settings.schema.json` | No `revision`, `rootID`, `sessionEpoch`, `suspended` | `internal/adapters/kubernetes/browser_settings.go`, `internal/bootstrap/hub_api_inputs.go`, session-epoch SQL (`internal/adapters/postgres/custodydb`) |
| `internal-work.schema.json` | Stream message on the connector connection: no `issuerEpoch`, `deliveryFence`, `*Ref`, `nodeBootID`, `StaleFence`, JWS wrapper; analysis input by `inputArtifactId` | `internal/adapters/jose/work.go`, `internal/contracts/work.go`, `internal/domain/fleet/work.go` |
| `local-key-service.schema.json`, `local-key-secret.schema.json` | wrap/unwrap only, no `validUntil`; purposes `artifact`, `browser-credentials` | `internal/contracts/key_service.go`, `internal/adapters/kms/local_signing.go`, `local_keys.go`, `protected_local_keys.go` |

Schemas kept because Go still embeds them with production code paths:
`work-trust`, `submission-trust` and `retention-topology`
(`internal/adapters/kubernetes/permission_decode.go` and their readers). Remove
each with its code.
`local-key-configuration.schema.json` had no runtime consumer and is deleted.
## ADR-335 contract divergence (2026-11-14)

The canonical contracts, examples and spec checkers follow ADR-335 (usable by
default), the maintainer decision that MCP and other clients carry the full
evidence access of the user they act for, and the standing rule that a limit
stays only with a written reason (resource cost, external constraint or
maintainer decision; see "Bounds in the contracts" in `specs/apis.md`). The
runtime still implements the earlier versions, kept under
`specs/contracts/implemented/` and `examples/implemented/` as in the ADR-330
pass. `scripts/permission-crds.py`, `profile-crd.py` and `retention-crd.py` now
also read through
`scripts/implemented_contracts.py`; all Go and console tests that read
examples go through `readImplementedExample` or the console equivalent.

| Contract | Canonical change | Runtime still implements (code) |
| --- | --- | --- |
| `mcp-tools.json`, `browser-openapi.yaml`, `operations.yaml` | 33 MCP tools: `get_extract(view)`, `query_artifact(operation)`, `download_artifact(action)`, `watch_live(action)`; recording-save preview in `preview_capture`; live sources in `list_recordings`; capture profiles in `list_diagnostics`; no `activate_policy`/`request_policy_grant`; every tool enabled by default | `internal/contracts/investigation_schema.go`, `investigation-schemas/*.json`; `internal/domain/audit/operation.go`, `connector_operation.go`; `internal/bootstrap/public_context.go`, `public_http.go`; `internal/application/authorization/policy_grant_attachment.go`; `internal/adapters/postgres/policy_grant_attachment.go` |
| `mcp-tools.json` | Names instead of IDs (`cluster`, workload, `policy`, recipe); reasons optional except `request_raw_access`; raw access by `artifact_ids` with defaulted size/expiry | `internal/transport/presentation/*_operations.go` |
| `artifact-download.schema.json` | Preparing/Ready/Completed/Failed/Cancelled; size and SHA-256 on every status; `content_path`, `browser_url`, `access_until`, bundle `representation`; no `continue_preparation`/`expires_at`/`resume_available` | `internal/transport/presentation/context_download.go`; console `web/src/evidence/evidence.ts` |
| `live-watch.schema.json`, `watch_live` | No watch deadline, duration or lifetime output cap; 10-minute idle close; no `sourcePage` | `internal/domain/live/source.go`, `watch.go` |
| `recording-save.schema.json`, `errors.yaml` | Rows with `owner_kind`/`save_via`/`live_projections`; `recordingSaves` default true; `NoCurrentSource` replaces `RecordingSelectionRequired` | `internal/transport/presentation/recording_save_history.go`, `recording_save_operations.go` |
| `investigation-access.schema.json`, grant views | No `clientIDs`: clients carry the user's access, raw and downloads included | `internal/application/authorization/grants.go`, `raw_query.go`; `internal/domain/authorization/grant.go`; `internal/adapters/postgres/access_grant.go`; `internal/transport/presentation/grant_operations.go` |
| `sharing-request`, `sharing-intent`, share schemas | No recipient cap (was 32/8), outputs/operations caps or `maxArtifactsPerCapture`; recurring `notAfter`/`maxCaptures` optional | Embedded `internal/adapters/kubernetes/policy-schemas/sharing-request.schema.json`; share admission in `internal/application/authorization` |
| `policy.schema.json`, `target.schema.json` | Budgets/retention/suspended/observation/evaluation/maxPods/selection/adoption optional; `adoption` default `followName`; no `observation.mode`, `grantRef` or hub-held `target.cluster`; optional `automationRef`; `workloadRef.apiVersion` optional | `internal/application/capture/policy_compile.go` (`pinUID` required, `allAuthorized` mode); `internal/adapters/kubernetes/policy_source.go`, `policy_source_hub.go` (`grantRef`, hub-held cluster; test reads `examples/implemented/policy-restart.yaml`); `internal/adapters/postgres/policy_grant_attachment.go`, `policy.go`, `policy_sources.go`; DebugPolicy CRD |
| `capture.schema.json`, `capture-composition.schema.json` | `recipeRef.digest`, `reason`, `idempotencyKey`, `deadline`, `maxTotalBytes`/`maxDuration`, `profileRef.version` optional | `internal/domain/planning/composition.go`; `internal/transport/presentation/recorder_preview.go`; console `web/src/capture` |
| `collection-scope.schema.json` | No `observation.mode` | `internal/application/capture/policy_compile.go`; console capture bundle |
| `action.schema.json`, `capture-profile-go-cpu.yaml` | Profile `impact` may be `observe` (pprof GET) | `internal/application/planning/profile_plan.go` (refuses non-intrusive); `internal/application/planning/profiles/go-cpu-v1.json` |
| `grant.schema.json` | Policy-grant `spec.renewal`, `status.renewalDue` | No renewal: `internal/application/authorization/grants.go`, `internal/adapters/postgres/policy_grant_attachment.go` |
| Capture/policy/trigger/recipe/packet/syscall schemas | No list-count caps; arbitrary maxima raised to 2^53−1; no packet-filter length cap (BPF limit checked at compile); `argv` items up to `MAX_ARG_STRLEN` | Embedded `policy-schemas/`, `permission-schemas/approval-policy`, manifest `profile` schema; `internal/domain/planning/composition.go` (`MaxCompositionComponents` 8, `MaxComponentEdits` 32, `MaxCompositionBytes`); generated DebugPolicy/CaptureProfile CRDs |
| `identity-settings.schema.json` | `groupsClaim`, `usernameClaim`, optional `requiredGroups`, `administrators`; no eligible lists, `groupMaxAgeSeconds`, `revision` or list caps | `internal/contracts/identity_settings.go`, `permission_runtime.go`, `installer_continuation.go`; `internal/domain/configuration/permissions.go`; `internal/bootstrap/permission_guards.go`; `internal/adapters/kubernetes/hub_worker_capacity_reads.go` |
| `browser-settings.schema.json` | `maxLifetimeSeconds` (default 7 d) and `inactivityTimeoutSeconds` (default 24 h); no `maxLogins`/`maxSessions`/`maxLogoutEvents` or per-user session count | `internal/contracts/browser_settings.go`, `installer_continuation.go`; `internal/domain/identity/browser_settings.go` |
| `access-binding`, `permission-common`, `cluster-access-binding` (new) | Subject `issuer` and `reason` optional; workload by name with optional `uid`; ClusterAccessBinding; `groupName` mapping mode; `reviewRef`/`guardRef` optional; no list or string caps beyond Kubernetes formats | `internal/adapters/kubernetes/permission_decode.go`; `internal/domain/configuration/permissions.go`, `review.go`; chart CRDs (no ClusterAccessBinding CRD) |
| `permission-source.schema.json` | `cluster` name instead of `clusterID`; no `maxDecisionAgeSeconds`; exclusions and `maxNamespaces` optional; access reviews map to any role | `internal/adapters/kubernetes/permission_decode.go`; `internal/domain/configuration/permissions.go` |
| `policy-authority.schema.json` | Envelope ceilings, `notAfter` and limits optional, no maxima | `internal/domain/authorization/automation.go`, `policy_grant.go`, `policy_grant_use.go` |

## Joining workload clusters with `mode: cluster` (ADR-331, 2026-11-14)

Branch `feat/hn-cluster-join` (on `feat/hn-remote-bindings`). The hub's
`clusters` values register remote clusters; the hub-api issues each join
Secret `<name>-join-<cluster>` (IDs, offer with `remote.*` addresses and
in-cluster server names, the cluster's own regional object-store
capabilities, a one-use bootstrap), derives each context-start entry and
in-process topology, and the connector delivers its capacity observation over
the lifecycle channel (migration 00163, after 00162 remote AccessBindings
). Owned kind clusters `asservat-cj-hub` (combined, bundled
services) and `asservat-cj-work` (`mode: cluster`, `region.joinSecret`):
`TestHelmNativeKindClusterJoin` passed (24.6 s) on a fresh install: Keycloak
sign-in, processing initialization, AccessBinding in the work cluster's
`apps-hn`, budget policy naming the joined cluster, MCP preview/request,
regional collection, verification, publication and native download through
the hub-local worker. `TestHelmNativeKindJourney` (combined, same values)
passed (45.5 s) on a second fresh install. The local runs used an uncommitted
no-op `00162` placeholder because the embedded schema requires contiguous
versions.

Maintainer correction (no polling where an event source exists), applied to
ADR-329 (c) and ADR-331: connectors watch AccessBindings and capacity
metadata (informers) and deliver only on change (≤ 1/s, digest-compared with
the hub's stored copy, no periodic resend); remote allows no longer expire;
a trigger in migration 00163 notifies `asservat_remote_bindings` /
`asservat_remote_capacity`, and the hub-worker LISTENs instead of reading the
rows each second (capacity rows stay in memory). Fresh kind runs:
`TestHelmNativeKindClusterJoin` passed (21.4 s); idle, neither delivery row
changed for 40 s; labelling the remote AccessBinding stored a new delivery
within 0.24 s. `TestHelmNativeKindJourney` passed (31.0 s) on another fresh
install. Real PostgreSQL: `scripts/test-custody.py --run
'^TestContextAdmissionWithRealServices$/^connector-identity-fast$'` passed,
including the trigger notification, stored digest and older-delivery
refusal (with the local `00162` placeholder). Not run: `make
permission-integration`, an image upgrade of a joined cluster, external
providers, a LoadBalancer or Gateway passthrough.

## AccessBindings in application namespaces (ADR-329, 2026-11-14)

Branch `feat/hn-accessbindings` on the Helm-native candidate. AccessBindings
live in the namespace they grant (no `spec.scope`; optional `spec.workloads`);
the hub-worker lists and watches them in every namespace of the hub cluster.
Namespace RBAC governs writers; a Helm-rendered ValidatingAdmissionPolicy
requires `bind` on `accessroles.asservat.io/<role>` (and `automation` for
`spec.automation`). The delegation envelope, the permission admission builder
and delegated previewers are removed. On a fresh all-bundled combined install
on the owned kind cluster `asservat-ab`, `TestHelmNativeKindJourney` passed
with the maintainer AccessBinding in the workload namespace `apps-hn`;
server dry-runs confirmed `edit` refused by RBAC, `admin` allowed, a writer
without `bind` refused, automation refused without the automation ClusterRole.
Not run: `make permission-integration` (its suite was adapted, not executed).

Follow-up branch `feat/hn-remote-bindings` (ADR-329 decision (c)):
`mode: cluster` connectors deliver their cluster's AccessBinding LIST every
10 seconds over the lifecycle channel (purpose `access-bindings`); the
federation validates and stores it under the cluster credential's cluster
(migration 00162); the hub-worker reconciler accepts it scoped to that
cluster (allows within 30 s of the delivery, denies until removed). Component
tests cover the reconciler, the real HTTP/2 lifecycle channel with a 4 MiB
delivery, federation attribution and the Kubernetes LIST/decode round trip.
Migration 00162 and the store/read adapter passed on real PostgreSQL in
`scripts/test-custody.py --run '^TestContextAdmissionWithRealServices$/^connector-identity-fast$'`
(store, older-delivery refusal, changed-row reread);
`make permission-integration` passed. Not run: a kind journey with a joined
`mode: cluster` connector (the chart cannot complete a `mode: cluster` join
yet) and the full custody suite.

## Helm-native installation (2026-11-14)

Candidate: PR #233 `feat/helm-native-install` (head `189f7f68`), following the
[plan](reviews/helm-native-install-plan.md) and
[field map](reviews/helm-native-field-map.md). The chart renders every
Kubernetes object. The `asservat secrets` pre-install/pre-upgrade hook Job
creates missing generated Secrets once and never rotates them. The ordinary
`asservat setup` Job (`<name>-setup-<hash>`) applies migrations, creates or
updates runtime SQL roles, seeds installation trust and configures bundled
OpenBao and SeaweedFS; hub workloads wait in a `wait-schema` init container.
In `mode: combined` hub-api issues the local connector's bootstrap into
`<name>-region-bootstrap`, so the connector self-enrolls without a manual step.
The installer Pod, its continuation, guards, journals and resume command are
removed.

A fresh all-bundled combined install (PostgreSQL, OpenBao, SeaweedFS,
Keycloak) on the owned kind cluster passes the full journey in
`test/integration/helm_native_kind_test.go` (`TestHelmNativeKindJourney`,
PASS in 24.06s at image `sha256:6cd289e5…`): Keycloak sign-in of a synthetic
human, processing initialization, MCP preview and pod-status capture,
verification and publication, and a 355-byte native download through the
hub-local worker. External providers, mixed provider combinations and
`mode: cluster` remote regions are not qualified with the Helm-native chart;
the hub publishes its regional offer only in combined mode. Installation docs:
[Install with Helm](installation/helm.md).

## Repo hygiene (2026-11-14)

Removed finished labs, the installer-era harness
modes and unreachable `test/integration` code. Gap: the installed journey
(`TestHelmNativeKindJourney`) has no CI suite. `--regional-context-start first`
fails on main and on this branch at the GC namespace-denial assertion
(`api_execution_native_test.go`), a guard check for the guards slice.

## Earlier qualification records

Records before 2026-11-14 are no longer kept in this file. Use
`git log -p -- docs/implementation-progress.md` to read them; commit 06d7a803a
is the last one that holds them in full.
