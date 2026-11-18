# Sustained implementation progress

## Registered workload clusters (2026-11-18)

The hub routes work to registered clusters on demand through the connector's
existing HTTP/2 connection. The router no longer polls for owners or requires
standby settings. Remove `clusters[].standby` and `hub.hub-api.public.standby`
on development upgrades. Upgrade both ends to protocol major 2. ADR-334
consolidates the registration, identity, dispatch and compatibility decisions.

- The former router, permission reader and download policy lost clusters at 17,
  65 and 33 entries respectively. Tests cover 65 registrations, a 129-cluster
  policy, and 201 populated deliveries with 20 ms injected SQL read and write
  latency. PostgreSQL accepted and acknowledged an 8,377,659-byte canonical
  audit event for 1,025 automation bindings. A separate real-services test
  accepted 65 decision-time sources and retained the provenance of cluster-wide
  Allow and Deny assignments through retirement.
- At `d4049fdfa`, a fresh two-cluster Kind installation ran two hub API and
  two federation replicas, with one connected remote cluster and 64 offline
  registrations. Two Helm upgrades withdrew and restored unchanged bindings on
  the same running connector. Across 36 idle seconds neither owner opened a
  native exchange. The permission epoch and sequence stayed constant while
  its lease advanced. Each public endpoint independently accepted a capture,
  replayed the duplicate, refused changed input, committed history and
  downloaded the selected Pod's 354-byte native file. Cleanup succeeded.
- SeaweedFS 4.53 rejected the former 210,581-byte evidence bucket policy.
  With permissions on the regional identities, the combined bucket-policy
  file measured 5,626 bytes for 65 registrations. On re-registration both
  withdrawn keys stayed unusable and the original evidence remained readable.
- The remote binding exchange now includes ClusterAccessBindings authored
  in the workload cluster. An unavailable binding observation blocks fresh
  decisions in that cluster. Namespace and workload metadata delivery from
  installed connectors is still pending. The key service accepts additive
  changes to mounted material. Original operation deadlines and the protection
  against mixing generations within one cryptographic operation still apply.
  Exact-source qualification for these changes is tracked in
  [PR #304](https://github.com/phihos/asservat/pull/304).

## Processing cleanup (2026-11-17)

Branch `codex/processing-cleanup`. Removed the dead manual processing
initialization action and its receipt state; roots still initialize at creation.
Migration 00005 removes the live SQL branch while preserving historical
decisions. Processing report operations no longer expose audit lanes or
intent/outcome acknowledgement flags. The added fetch-body workaround is confined to the processing journey; other
browser drivers use their main-branch implementations.
Canonical, runtime and generated console contracts are updated together.
Verification: the schema-5 processing/setup SQL fixture and all 14 console
browser suites pass; owned service cleanup completed. Earlier build/vet, focused
Go tests, nine static gates and console-check (658 tests) passed. The full Go
race gate had bootstrap/MCP/presentation deadline failures; its retry was
interrupted by disk exhaustion and was not repeated in the completion pass.
Review correction (2026-11-18): removed the shared response helper and restored
the other browser scripts from main. Both console gates pass under the shared
integration lock: 658 console tests and all 14 browser suites.
Next: PR review and the remaining full Go gate. No installed collection
qualification is claimed.

## One schema baseline (2026-11-17)

Branch `clean/migration-baseline`. The pre-release chain 00001–00201 is
replaced by `migrations/00001_baseline.sql`, which creates the head schema
directly; there is no upgrade path from the old chain (nothing was released).
Schema version 1. Migration numbers below refer to the removed chain. Tests
that probed old migration text, Down sections or upgrades from an older head
are gone. Verification: a database migrated by the old chain and one by the
baseline have identical catalogs (functions, triggers, columns, constraints,
indexes, privileges, no seed rows); four CHECK constraints differ only in
PostgreSQL's flattening of nested `AND`.

## Stateless previews (ADR-330 D9, 2026-11-17)

Branch `clean/previews-api`. A preview stores nothing: `preview_capture` and
`preview_recording_save` return `plan_digest`; `request_capture` takes the
reviewed `preview` request, `expected_plan_digest` and `idempotency_key`,
recomputes the plan and refuses a different one with `ReviewChanged`. The
request ID and every plan ID (capture, case, attempt, snapshot) derive from
the requester, key and plan digest, so a retry names the same capture and
the same pending approval; `context_capture.preview_id`,
`recording_save_group.preview_id` and `access_grant.preview_id` hold that
request ID. Migration 00200 drops `context_preview`, its fences and expiry.
Removed: the preview store, preview cleanup, `resolve_capture_request`,
`continue_acquisition`, the `capture-resolution` SQL duty, the per-root
preview cap and `preview_id` in grant replies.
Gaps: a request recomputes the preview's reads before admission. Recording
handles still expire after one minute.

## Approval submits the request (ADR-335 D5, 2026-11-17)

Branch `clean/approval-submit`. An ad hoc grant stores the `request_capture`
input with the requester's verified groups, scopes, identity policy revision
and the end of their authentication (00201 `access_grant.submission`).
`decide_review` approve submits it right after the decision commits, through
the `request_capture` path, so current bindings and denies decide. After that
end it returns the warning `RequesterReauthenticationRequired`, `get_grant`
sets `can_resume` and the requester resubmits. The console waits for the
capture on the status stream, which now waits for a capture not yet visible.
A grant decision notifies its capture ID; without a visible capture the
stream ends with `accessLost` and the console rereads the grant.

## One-step publication (REQ-EVD-001, ADR-330, 2026-11-17)

Branch `clean/publication`. hub-api publishes in the transaction that records
the collector's stored outcome (`RecordAPIStoredCompletion`): copy receipts,
the catalog row (admitted facts plus the reported copy digest, native size and
Go-profile acquisition window) and the custody event; the catalog INSERT
triggers add the case association, capture-time shares and the progress
`NOTIFY`; a `capture.publish` `audit_event` row commits with it. Migration 00199 drops `context_verification` and
`context_key_unwrap`. Removed: the `asservat publisher` Deployment, its
verifier key unwrap, verifier PKI, OpenBao audit key, SeaweedFS principals,
SQL purposes and Helm values; `ContextPublisher`, `ContextPublicationGate`,
verification audit objects and receipts. The producer now runs the
headers-only, raw-cap and approved-HTTP-header checks before encryption.
Verified: see the PR. Gaps: reads compare the manifest with the admitted facts
and copy digests but not yet with the stored native size.

## Custody fixes after #279 and #283 (2026-11-17)

Branch `clean/main-fixes-downgrade`. The integration hub pool fixture opens the
one 20-connection ordinary pool (#283 removed the resolution lanes). A first
API preparation refused for lack of headroom again reports execution
`ErrUnavailable`/`ErrNotStarted` (#279 renamed the ledger cause). Content
audit counts are scoped to their subtest. The 00102 Down probe against the
head schema is deleted; `policy_grant_migration_test` keeps the real
schema-102 Down. Verified: the native-download subtests, api-execution
preparation boundaries, custody shard 4.

## Audit as a database row, part 1 (ADR-330 D6, REQ-AUT-005, 2026-11-17)

Branch `clean/audit-api`. `audit_event` (00191) holds one append-only row per
event: one `call` row per admitted public operation, and one row per effect
written in the effect's own transaction (shares 00192, context queries 00193,
capture admission 00194, download stop 00195, processing decisions 00196).
00197 drops the encrypted operation audit: `operation_audit*` tables, the
`capture_operation_*` views, `capture_audit_root`, their guards and history
functions. Capacity creates no audit pool and enrollment reserves no audit
account. Removed in Go: the operation journal/acknowledgement/lifecycle,
overdue and history cleanup, the hub-worker cleanup child, its four OpenBao
cleanup roles and the `operation-cleanup`/`operation-verify` S3 principals,
the capture audit SQL logins (`capture-intent-read`, `capture-journal`,
`capture-ack`, `capture-cleanup`, `capture-verifier`, `capture-finalizer`)
and the HTTP audit lanes.

Gaps: the presentation layer still builds an `OperationIntent`/`Outcome`
before writing the call row; stateless previews and the MCP/browser surface
of the canonical contracts are the next steps. The capacity root backing still
carries `Capture`/`Normal`/`Resolution` audit lane qualifications that only
size `download_control_allocation` and native backing. Other encrypted audit
receipts (download batches and workers, owner/worker enrollment, retention,
permission authority, context deletion) are unchanged. A `goose down-to 125`
probe no longer works: about thirty historical migrations name the dropped
tables; our migrations have no Down and re-Up of 00191-00197 is safe.

## Retention as stored deadlines (ADR-330 D12, 2026-11-15)

Branch `clean/retention`. Migration 00190 drops the retention source,
epoch, checkpoint and catch-up tables; `retention_policy` holds the stored
policy set, `retention_policy_event` one audit row per applied or removed
policy. The hub-worker `RetentionFollower` lists and watches
`EvidenceRetentionPolicy` and stores the set; each new or changed policy
shortens matching deadlines with one `retention_policy_effect` update in the
same transaction, and an admission trigger applies stored policies to each new
capture (taking a shared advisory lock that the follower holds exclusively,
and evaluating only policies covering the row's cluster). An invalid policy
is stored as rejected: the valid ones apply, the rejected one refuses new
collection in its cluster scope (all clusters when unreadable) and is logged
once per generation. `RetentionProof`, `RetentionTransactionGuard`, retention topology
contracts and schema, accepted-source readiness, per-read re-resolution and
the key-service/publisher catalog polling loops are gone. Verified: focused custody
(`^d`, retention, deletion, publication, history: 98 subtests pass), goose
up/down-to 125/up on PostgreSQL 17, `make go-check pcap-check` and the CI
gate set.
Label selectors (migration 00198): target resolution reads the namespace and
workload labels, `MatchPolicies` applies matchLabels, and admission records the
labels on `context_capture.target_labels` so policy events and the admission
trigger shorten only matching artifacts. Policy recorders and saved windows
use the labels resolved at arming. Rows without recorded labels (older rows)
take a labeled policy cluster-wide.
Open: policy status writes (no RBAC or status code yet; the log line is the
signal), connector-pushed local policies.

## Joined clusters without copied Secrets (REQ-FED-001/002, ADR-334/335 D4, 2026-11-16)

Branch `clean/join`. A workload cluster's release needs only `mode: cluster`,
`hub.url` (+ optional `hub.caBundle`); the hub lists it in `clusters` by name
and issuer/JWKS and derives its ID from the name. On connect the federation
answers a `settings` conversation with the cluster and peer IDs, the stored
offer and the cluster's own regional object-store capabilities, and relays
tunnels (`/v1/connector-tunnel`, ServiceAccount token, ends at token expiry)
to the owners, key service and evidence store named in the offer; the
connector keeps its own TLS session with each inside the tunnel, so evidence
uploads travel over the hub connection. Combined mode uses the same path
(in-cluster federation URL, federation CA), so the connector no longer mounts
the IDs Secret, the offer ConfigMap or object-store Secrets. Removed: the join
Secret and its runner, `remote.*`, `region.joinSecret`/`offerConfigMap`/
`hub.*`/`executor.evidenceSecret`, `clusters[].clusterID`, the offer's
federation section and passthrough server names. `region.executor.
profileAuthorization` names a local Secret. The hub.url host is added to the
federation's generated certificate. Also fixed: since #260 the combined hub-api
could not start (`observation-ingress` invalid: no peers and no local
capacity handler); it now serves no observation without peers.

Owned kind clusters `asservat-jn-hub`/`-work` (deleted): the work connector
received its settings and AccessBindings were delivered; the regional
pod-status capture in the joined cluster was collected, verified and
published through the tunnels. `TestHelmNativeKindClusterJoin` and the
combined `TestHelmNativeKindJourney` both then fail at native download
(`download content refused: content/transfer/window (invalid)`,
`BeginDownloadWindow`); origin/main with only the observation fix fails the
combined journey the same way. Gaps: `hub.url` reaches
the federation Service, not the console origin; the lifecycle conversations
and tunnels share one HTTP/2 connection but work is not yet pushed on it.

## Native download window deadline (2026-11-16)

Native downloads failed at `content/transfer/window (invalid)` since #260:
capacity accounts give the download control the standing date (migration
00172), and SQL pins each window's audit `WriteUntil` to it, but the domain
still capped `WriteUntil` at start + 24 h 5 min. The cap is removed; the
response's own bounds end a transfer (ADR-312). Owned kind cluster
`asservat-dl-hub` (deleted): combined `TestHelmNativeKindJourney` passes end
to end, including the native download.

## Integration tests on the simplified schema (2026-11-16)

Context query admission failed for every query: `guard_context_query`
still required the `RecoveryIssuerEpoch`/`RecoveryRevision` keys that #263
removed from the stored query. Migration 00189 drops both from the guard
and drops the unused `context_query_qualification_valid`, which called a
function 00172 removed.
Tests that exercised removed machinery are deleted: the head-specific
blocks of the schema upgrade test, the dropped
`capacity_context_protocol_backing` and `context_query_qualification_valid`
checks, the removed share-expiry refusal (the adapter now clamps) and
migration downgrades below 125. `scripts/test-custody.py --libpcap` runs the
libpcap-tagged workflow tests. Query refusals now name the inner step.

## Static fleet trust (ADR-330 D1/D13, 2026-11-15)

The fleet trust row is static installation identity that `asservat setup`
seeds (installation ID, issuer epoch). The hub-worker's one-second fleet
observer, `fleet_observation`, `observe_fleet_administration`,
`fence_fleet_observation`, the semantic-version trigger and the trust
suspension are removed (migration 00185). `fleet_current_trust` keeps
`suspended` (false) and `observed_at`/`fresh_until` (-infinity/infinity) for
the stored function bodies that still name them. Provider and audit work no
longer waits for a fleet observation after admission.

Verified: see the PR. Gap: the `configuration-fleet` SQL login now only waits
for the schema in the hub-worker init container.

## Download caps removed (ADR-312, ADR-335 D9, 2026-11-15)

A download session runs to its original authority, access and allocation
bounds. Removed: the 1024-request cap and request counter, the fixed 8-hour
session and response ceilings, the configured session duration, the
per-identity download limit and `downloadMaxSeconds`, and the hard-coded
per-user and per-installation stream and worker counts (migration 00183).
`downloadConcurrency` stays per hub-api replica; the download Job keeps its
runtime ceiling while worker certificate epochs exist. The control
allocation keeps its 1024 partial windows (`artifact.DownloadPartialWindows`,
seeded by 00172), which bound window audit bytes.

Verified: `go build`, `go vet` (also `-tags libpcap`), `make go-check
pcap-check`, the CI gate set, focused download custody tests (real
PostgreSQL).

## Acquisition worker caps removed (ADR-335 D9, 2026-11-15)

Projection and query workers no longer check the 16 per installation, two
per workload and two per principal caps. Removed: the worker-room check,
`ErrBusy` and its busy refusal, the count query, and the `download_worker`
principal key and index (migration 00186). Query units and the capacity
concurrency limit bound expensive work.

## Live watch without lifetime (ADR-335 D9, 2026-11-15)

A live watch ends with its sources or after 10 idle minutes; it has no
duration or total output cap (migration 00182). `read_live_watch` waits up
to 30 s (`wait_ms`) instead of returning `retry_after_ms`. Rows expire at
their privacy or watch end; source handles stay valid while the source is
unchanged. The 16-source, 16-predicate and 5-minute manual source caps are
gone. Per-viewer rate, rows, buffer and the batch envelope stay.

Verified: `go build`, `go vet`, `make go-check pcap-check`, the CI gate set,
`make console-check`, focused live custody tests (real PostgreSQL). Gaps:
the five live tools are not yet the single `watch_live` tool.

## Limits without a reason removed (2026-11-15)

Streaming artifacts may use S3's 10,000 parts of one 8 MiB frame (about
77 GiB, migration 00180); the journal keeps only the latest part. Workload
Pod lists follow LIST continue tokens. Composition, catalog, filter-text,
SQL-password maximum and ConfigMap-size caps are gone. pprof windows (were
60 s CPU, 15 s trace, 60 s delta) and argument observations run to the
configured duration; the target's pprof server refuses a duration it cannot
serve. The recorder ring is `{maxAge, maxBytes, segments}`; the
encrypted-disk medium and the syscall `maxEvents` count are removed.
Recorder and saved-log windows run to the configured duration (migration 00181).

Verified: `go build`, `go vet` (also `-tags libpcap`), `make go-check
pcap-check`, the CI gate set, `TestCustodyWithRealServices/bounded_streaming`
(real PostgreSQL). Gaps: embedded policy schemas still carry list caps.

## Permission CRDs follow the canonical contracts (ADR-335 D1/D4/D14, 2026-11-15)

No blocking initial AccessBinding review: the first permission batch is
accepted without a bootstrap review. AccessBinding subject `issuer` and
`reason` are optional and workload `uid` is optional: a workload named
without uid matches by kind and name through `workload_name`, which the hub
fills with every Deployment/StatefulSet it resolves (migration 00188); a uid
pins one instance. PermissionSources name
their `cluster` (`local` or a joined cluster) and have no
`maxDecisionAgeSeconds`/`maxNamespaces`; access reviews map to any role.
New cluster-scoped ClusterAccessBinding CRD, accepted as one all-namespace
basis per cluster (migration 00179), or with `namespaceSelector` as one basis
per selected namespace of the cluster's label observation; while those labels
are unknown an allow grants nothing and a deny covers every namespace. The
unconsumed `privacy-operator` role is gone (a privacy operator is an
administrator). Runtime guard proofs, the groupID
directory and the permission scale caps are gone. Verification:
`make permission-integration`, focused custody permission subtests.

## Identity and browser settings follow the canonical contracts (ADR-335 D1/D4/D5/D8, 2026-11-15)

`identity.json` carries `groupsClaim`, `usernameClaim`, optional
`requiredGroups` and required `administrators`; eligible lists, group age and
`revision` are gone, and `requireRecordingApproval` with its settings reads.
Step-up is optional and off by default. Browser sessions end at creation plus
`maxLifetimeSeconds` (7 d) or after `inactivityTimeoutSeconds` (24 h); session
roots, epochs, the settings projection and its polling loop are removed
(migration 00177). Processing is initialized when its root is created
(migration 00178); bundled Keycloak emits group paths in `groups` and has no
processing-operator group.

## Grants cover every client of the requester (ADR-335 D5, 2026-11-15)

An approved ad-hoc or raw-query grant covers matching published artifacts for
the requesting human on every client: one registration per artifact counts
`maxArtifacts`, no per-client children or `clientIDs`. No one-hour review
window; result access ends at its `notAfter`. Step-up is optional: SQL accepts
an approval without `acr`/`auth_time` and records them when present.
Migration 00176. Verification: custody raw-grant, access-grant and
policy-recorder grant subtests pass.

## Shares without caps or Suspended state (ADR-335 D7, 2026-11-15)

A share lasts until the artifact's access ends unless the creator names an
earlier end. No Suspended phase or administrator resume; managers are members
of a managing group now. The 24 h/7 d lifetime, recipient and manager counts,
32 active shares per artifact and the 100-capture policy limit are gone.
Migration 00175 drops the SQL checks; the runtime reads the canonical
`sharing-request` schema. Verification: custody `TestContextAdmissionWithRealServices`
share subtests; the two `policy-share-*` subtests fail identically on main
(context admission unavailable).

## Recovery proof removed (2026-11-15)

Branch `clean/recovery-2`. Migration 00173 removes
`fleet_current_trust.recovery_blocked` from the view and from every stored
function body; its Down restores the 00167 view for downgrade probes.
`RecoveryProof`, `RecoveryState`, every `RecoveryReader`,
`RecoveryTransactionGuard` and `EffectTransactionGuards` are gone from domain,
application, adapters, bootstrap and transport; effect transactions no longer
lock or check the trust row for recovery. Open: the setup recovery step of REQ-DB-005;
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

Follow-up (branch `clean/capacity-gaps`, migration 00187): target
resolution marks `kube-*`, the release namespace and namespaces labelled
`asservat.io/evidence: disabled`; new collection there is refused
(`targets.ErrEvidenceDisabled`), reads still resolve. A profile
admission counts the workload's still-writable profile attempts under the
allocation lock (`capacity_expensive_admits`) and refuses at
`maxConcurrentExpensive`. The spec now divides the default share by enrolled
workloads (an all-cluster workload inventory would add watches for no
benefit) and drops `onFull`/`DeleteOldestEligibleInAccount`: a full account
rejects new expensive work. Gap: no expensive request waits; one that finds
the limit reached is refused at once.

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
is not enforced; capacity is on only when a value is set; the
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
removed. The join Secret is gone too: see "Joined clusters without copied
Secrets" below; the node channel is in "Node channel stream" below.

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
depended on the reader.

Gaps: `administrators` is optional in the
implemented identity copy until the identity reader adopts the canonical
contract; the `fleet-operator` role name stays in docs/interfaces.

## Plain work frames (ADR-330 D2, 2026-11-15)

Branch `clean/connector-3a`. Context-start, history and source work are plain
JSON frames on the authenticated connector stream; the connector accepts only
work naming its own channel and cluster. Removed: the work JWS signers and
verifiers, hub-held and connector work trust (sources, guards, catalog
`workTrust` slots, the offer's `workKey`), the OpenBao `work-signing` key and
`work-sign` role, the lifecycle `recovery` purpose and the federation's
`connector-read` SQL duty, policy-submission signing (dead since ADR-330) and
the key service's `sign` operation, `policy-submission` purpose and request
`version`. Hub authorization and SQL checks before sending work are unchanged.

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
| `mcp-tools.json`, `browser-openapi.yaml` | Pending results carry `revision`; `get_capture`/`get_grant`/`get_query_result`/`get_artifact_download` take `after_revision` and wait ≤30 s; `get_capture` has no poll advice | No `after_revision` wait (the request-scoped identity and audit windows end after 5–20 s); query results keep `retry_after_seconds`: `internal/transport/presentation/context_projection_operations.go` |
| `browser-openapi.yaml` | SSE: `GET /api/v1/events` (`StatusEvent`), `GET /api/v1/live/watches/{watch_id}/events` (`live-watch.schema.json#/$defs/event`) | `/api/v1/events` serves `capture_id` only (`internal/transport/browser/events.go`); grant, download and query events and the live-watch stream are missing; console still polls queries and live watches |
| `mcp-tools.json` | `explain_access`/`preview_access_change`: `ClusterNotObserved` replaces `PermissionObservationStale`; no `valid_until` | `internal/domain/authorization/explain.go`, `internal/transport/presentation/access_preview_operations.go` |
| `live-watch.schema.json`, `read_live_watch` | `wait_ms` ≤30000; no `retry_after_ms`, `row_max_age_seconds`, `managed_row_max_age_seconds`, source `handle_expires_at`; row expiry is min(privacy, watch deadline) | `internal/domain/live/watch.go`, `internal/domain/live/source.go`, `internal/application/live/service.go` |
| `capture-assessment.schema.json` | No `validUntil` | `internal/application/planning/context_assessment.go`, `recorder_assessment.go` |
| `packet-capture.schema.json` | No `peers.maxStaleness` (peers follow watch events) | `internal/application/planning/peers.go`, `recorder.go`, builtin profiles `internal/application/planning/profiles/*.json`, `internal/bootstrap/regional_peer_verifier.go`; DebugPolicy/CaptureProfile CRDs |
| `local-key-service.schema.json`, `local-key-secret.schema.json` | No `validUntil`; purposes `artifact`, `browser-credentials` | Response `validUntil` and the `audit` purpose: `internal/contracts/key_service.go`, `internal/adapters/kms/local_keys.go`, `internal/domain/authorization/key_service.go` |

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
| `live-watch.schema.json`, `watch_live` | One `watch_live` tool; no `sourcePage` | `internal/domain/live/source.go`, `watch.go` |
| `recording-save.schema.json`, `errors.yaml` | Rows with `owner_kind`/`save_via`/`live_projections`; `recordingSaves` default true; `NoCurrentSource` replaces `RecordingSelectionRequired` | `internal/transport/presentation/recording_save_history.go`, `recording_save_operations.go` |
| `policy.schema.json`, `target.schema.json` | Budgets/retention/suspended/observation/evaluation/maxPods/selection/adoption optional; `adoption` default `followName`; no `observation.mode`, `grantRef` or hub-held `target.cluster`; optional `automationRef`; `workloadRef.apiVersion` optional | `internal/application/capture/policy_compile.go` (`pinUID` required, `allAuthorized` mode); `internal/adapters/kubernetes/policy_source.go`, `policy_source_hub.go` (`grantRef`, hub-held cluster; test reads `examples/implemented/policy-restart.yaml`); `internal/adapters/postgres/policy_grant_attachment.go`, `policy.go`, `policy_sources.go`; DebugPolicy CRD |
| `capture.schema.json`, `capture-composition.schema.json` | `recipeRef.digest`, `reason`, `idempotencyKey`, `deadline`, `maxTotalBytes`/`maxDuration`, `profileRef.version` optional | `internal/domain/planning/composition.go`; `internal/transport/presentation/recorder_preview.go`; console `web/src/capture` |
| `collection-scope.schema.json` | No `observation.mode` | `internal/application/capture/policy_compile.go`; console capture bundle |
| `action.schema.json`, `capture-profile-go-cpu.yaml` | Profile `impact` may be `observe` (pprof GET) | `internal/application/planning/profile_plan.go` (refuses non-intrusive); `internal/application/planning/profiles/go-cpu-v1.json` |
| `grant.schema.json` | Policy-grant `spec.renewal`, `status.renewalDue` | No renewal: `internal/application/authorization/grants.go`, `internal/adapters/postgres/policy_grant_attachment.go` |
| Capture/policy/trigger/recipe/packet/syscall schemas | No list-count caps; arbitrary maxima raised to 2^53−1; no packet-filter length cap (BPF limit checked at compile); `argv` items up to `MAX_ARG_STRLEN` | Embedded `policy-schemas/`, `permission-schemas/approval-policy`, manifest `profile` schema; generated DebugPolicy/CaptureProfile CRDs |
| `identity-settings.schema.json` | `groupsClaim`, `usernameClaim`, optional `requiredGroups`, `administrators`; no eligible lists, `groupMaxAgeSeconds`, `revision` or list caps | `internal/contracts/identity_settings.go`, `permission_runtime.go`, `installer_continuation.go`; `internal/domain/configuration/permissions.go`; `internal/bootstrap/permission_guards.go`; `internal/adapters/kubernetes/hub_worker_capacity_reads.go` |
| `browser-settings.schema.json` | `maxLifetimeSeconds` (default 7 d) and `inactivityTimeoutSeconds` (default 24 h); no `maxLogins`/`maxSessions`/`maxLogoutEvents` or per-user session count | `internal/contracts/browser_settings.go`, `installer_continuation.go`; `internal/domain/identity/browser_settings.go` |
| `access-binding`, `permission-common`, `cluster-access-binding` (new) | Subject `issuer` and `reason` optional; ClusterAccessBinding; `groupName` mapping mode; `reviewRef`/`guardRef` optional; no list or string caps beyond Kubernetes formats | `internal/adapters/kubernetes/permission_decode.go`; `internal/domain/configuration/permissions.go`, `review.go`; chart CRDs (no ClusterAccessBinding CRD) |
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
