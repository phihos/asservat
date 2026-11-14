# Sustained implementation progress

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

## ADR-330 contract divergence (2026-11-14)

The canonical contracts in `specs/contracts/` and `docs/interfaces/` follow
ADR-330. The runtime still implements the earlier versions, which are kept
byte-for-byte under `specs/contracts/implemented/` and `examples/implemented/`.
Runtime consumers read through them: the embedded Go schema bundles
(`scripts/manifest-schemas.py`, `scripts/investigation-schemas.py`), the
generated CRDs (`scripts/policy-crd.py`, `scripts/capacity-crds.py`), the
console contract generator (`web/scripts/contracts.mjs`) and the Go/console
tests that load contracts or examples. Spec gates validate only the canonical
files. Delete an `implemented/` file in the change that makes its runtime
implement the canonical contract.

| Contract | Canonical change | Runtime still implements (code) |
| --- | --- | --- |
| `mcp-tools.json`, `browser-openapi.yaml` | Stateless previews: `plan_digest` out, `preview` + `expected_plan_digest` + `idempotency_key` in; `resolve_capture_request` and `continue_acquisition` removed | Stored preview handles, resolution tool and continue flag: `internal/transport/presentation/context_operations.go`, `recording_save_operations.go`, `recorder_preview.go`; `internal/domain/audit/operation.go`; `internal/bootstrap/public_context.go`; console `web/src/capture`, `web/src/recordings` |
| `mcp-tools.json`, `browser-openapi.yaml` | Pending results carry `revision`; `get_capture`/`get_grant`/`get_query_result`/`get_artifact_download` take `after_revision` and wait ≤30 s; `get_capture` has no poll advice | `retry_after_seconds` poll advice: `internal/transport/presentation/context_projection_operations.go`, `context_operations.go`; console status polling |
| `browser-openapi.yaml` | SSE: `GET /api/v1/events` (`StatusEvent`), `GET /api/v1/live/watches/{watch_id}/events` (`live-watch.schema.json#/$defs/event`) | Not implemented; console polls |
| `mcp-tools.json` | `get_grant`/`list_reviews`/`request_policy_grant` drop `preview_id`, `can_resolve`, `resume_requires_original_client` | `internal/application/authorization/grants.go`, `internal/transport/presentation/grant_operations.go` |
| `mcp-tools.json` | `explain_access`/`preview_access_change`: `ClusterNotObserved` replaces `PermissionObservationStale`; no `valid_until` | `internal/domain/authorization/explain.go`, `internal/transport/presentation/access_preview_operations.go` |
| `mcp-tools.json`, `live-capacity.schema.json` (deleted) | `get_live_capacity` removed; live load is Prometheus metrics (REQ-LIV-004) | `internal/transport/presentation/live_capacity_operations.go`, `internal/contracts/investigation_schema.go`, `internal/domain/audit/operation.go`, `web/src/capacity` |
| `live-watch.schema.json`, `read_live_watch` | `wait_ms` ≤30000; no `retry_after_ms`, `row_max_age_seconds`, `managed_row_max_age_seconds`, source `handle_expires_at`; row expiry is min(privacy, watch deadline) | `internal/domain/live/watch.go`, `internal/domain/live/source.go`, `internal/application/live/service.go` |
| `recording-save.schema.json` | Preview has `plan_digest` instead of `preview_id`/`capture_id`/`expires_at`/`save_scope_digest`; no recording `handle_expires_at` | `internal/transport/presentation/recording_save_operations.go`, `internal/domain/live/source.go` |
| `capture-assessment.schema.json` | No `validUntil` | `internal/application/planning/context_assessment.go`, `recorder_assessment.go` |
| `packet-capture.schema.json` | No `peers.maxStaleness` (peers follow watch events) | `internal/application/planning/peers.go`, `recorder.go`, builtin profiles `internal/application/planning/profiles/*.json`, `internal/bootstrap/regional_peer_verifier.go`; DebugPolicy/CaptureProfile CRDs |
| `browser-settings.schema.json` | No `revision`, `rootID`, `sessionEpoch`, `suspended` | `internal/adapters/kubernetes/browser_settings.go`, `internal/bootstrap/hub_api_inputs.go`, session-epoch SQL (`internal/adapters/postgres/custodydb`) |
| `budget-policy.schema.json` | `spec.priority`; breaker `pressureTriggers` (PSI) + `recoverySeconds` replace `unhealthySamples`/`sampleIntervalSeconds`/`recoveryHealthySeconds` | Embedded copy `internal/adapters/kubernetes/capacity-schemas/`, chart CRD `evidencebudgetpolicies.yaml`, Helm values (`examples/helm/context-trial-profile.yaml`, `internal/bootstrap/testdata/`); no priority selection |
| `internal-work.schema.json` | Stream message on the connector connection: no `issuerEpoch`, `deliveryFence`, `*Ref`, `nodeBootID`, `StaleFence`, JWS wrapper; analysis input by `inputArtifactId` | `internal/adapters/jose/work.go`, `internal/contracts/work.go`, `internal/domain/fleet/work.go` |
| `local-key-service.schema.json`, `local-key-secret.schema.json` | wrap/unwrap only, no `validUntil`; purposes `artifact`, `browser-credentials` | `internal/contracts/key_service.go`, `internal/adapters/kms/local_signing.go`, `local_keys.go`, `protected_local_keys.go` |
| (no JSON schema) node channel | Hello with version and capabilities; no enroll/poll, CSR, boot ID or epoch | `internal/contracts/node_channel.go`, `internal/bootstrap/node_channel.go` |

Schemas kept because Go still embeds them with production code paths:
`work-trust`, `submission-trust`, `installation-witness`, `retention-topology`
(`internal/adapters/kubernetes/permission_decode.go` and their readers), and
`local-start` with `scripts/start-crd.py` and
`charts/asservat/crds/capacityreservations.yaml`
(`internal/adapters/kubernetes/start_admission.go`). Remove each with its code.
`local-key-configuration.schema.json` had no runtime consumer and is deleted.
## ADR-335 contract divergence (2026-11-14)

The canonical contracts, examples and spec checkers follow ADR-335 (usable by
default), the maintainer decision that MCP and other clients carry the full
evidence access of the user they act for, and the standing rule that a limit
stays only with a written reason (resource cost, external constraint or
maintainer decision; see "Bounds in the contracts" in `specs/apis.md`). The
runtime still implements the earlier versions, kept under
`specs/contracts/implemented/` and `examples/implemented/` as in the ADR-330
pass. `scripts/permission-crds.py`, `profile-crd.py`, `retention-crd.py` and
the `storage-pool` input of `capacity-crds.py` now also read through
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
| `budget-policy`, `storage-pool` | Share percentages, all fields optional, `scope.clusters` by name, optional `protectedAllocations` | `internal/adapters/kubernetes/capacity_decode.go` (`workloadSlots`), `capacity-schemas/`, chart CRDs |
| Capture/policy/trigger/recipe/packet/syscall schemas | No list-count caps; arbitrary maxima raised to 2^53−1; no packet-filter length cap (BPF limit checked at compile); `argv` items up to `MAX_ARG_STRLEN` | Embedded `policy-schemas/`, `capacity-schemas/`, `permission-schemas/approval-policy`, manifest `profile` schema; `internal/domain/planning/composition.go` (`MaxCompositionComponents` 8, `MaxComponentEdits` 32, `MaxCompositionBytes`); generated DebugPolicy/CaptureProfile/capacity CRDs |
| `identity-settings.schema.json` | `groupsClaim`, `usernameClaim`, optional `requiredGroups`, `administrators`; no eligible lists, `groupMaxAgeSeconds`, `revision` or list caps | `internal/contracts/identity_settings.go`, `permission_runtime.go`, `installer_continuation.go`; `internal/domain/configuration/permissions.go`; `internal/bootstrap/permission_guards.go`; `internal/adapters/kubernetes/hub_worker_capacity_reads.go` |
| `browser-settings.schema.json` | `maxLifetimeSeconds` (default 7 d) and `inactivityTimeoutSeconds` (default 24 h); no `maxLogins`/`maxSessions`/`maxLogoutEvents` or per-user session count | `internal/contracts/browser_settings.go`, `installer_continuation.go`; `internal/domain/identity/browser_settings.go` |
| `fleet-settings.schema.json` (deleted) | Administrators replace fleet operators (D14) | `internal/adapters/kubernetes/fleet_settings.go`, `initial_preparer_inputs.go`, `initial_bootstrap_plan.go`, `hub_workload.go`, `configuration_runtime_*.go`; `internal/bootstrap/hub_api_inputs.go`; `internal/contracts/owner_deployment.go` |
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

## Earlier qualification records

Records before 2026-11-14, and the generated reports under `test/results/`,
are no longer kept in the tree. Use `git log -p -- docs/implementation-progress.md`
or `git log -- test/results/` to read them; commit 06d7a803a is the last one
that holds both in full.
