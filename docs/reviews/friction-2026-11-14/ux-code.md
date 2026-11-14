# Operator/user friction in the code and chart today (main 5d4667715)

Scope: what `cmd/`, `internal/`, `web/src`, `charts/asservat`, the install docs,
`docs/implementation-progress.md` and the homelab install
(`~/Quellcode/K8S-CD-worktrees/asservat-homelab/asservat`) impose today. Paths are
relative to `/home/phil/Projekte/asservat-ux`. Excluded as KNOWN (ADR-334): join
Secrets, bootstrap records, the four connector endpoints, image-digest pinning.

"ADR-330" says whether the rewritten spec already removes the cause. If it does,
the item is an implementation gap and keeps its priority. "Origin" is
**maintainer** only when the AGENTS.md "Authority and invariants" section
requires it. Everything else is **agent**.

## Summary

| Severity | Count |
| --- | --- |
| High | 14 |
| Medium | 15 |
| Low | 7 |

Top 5:

1. **U-01**: changed capacity values are silently ignored after the first install.
2. **U-02**: the connector waits forever once the write-once regional offer is older than one hour. This happened on the homelab.
3. **U-04**: users type cluster UUIDs, namespace UIDs and workload UIDs everywhere, including the console capture form.
4. **U-05**: the chart has no usable production defaults. Only the trial profile works, with 5-minute evidence retention and 8 browser sessions for the whole installation.
5. **U-03**: if any AccessBinding exists before the hub-worker's first acceptance, the permission reconciler wedges until someone adds a hand-written review ConfigMap.

---

## High

### U-01 Capacity settings are fixed at first install, and changes are dropped silently
- `internal/bootstrap/hub_worker_capacity_child.go:107-116`, `internal/adapters/postgres/capacity_initialization.go:30-47` (`CapacityDifferent`: "a present root is never changed"), `internal/adapters/postgres/capacity_cluster_qualification.go:18-40` (write-once regional qualification including `namespaceKeys`).
- **Effect:** an operator raises `capacity.accounts`, the footprints, the envelope, the backends, the lanes, `namespaceKeys` or the backup settings and runs `helm upgrade`. The upgrade succeeds, but the hub-worker prints one stderr line and keeps the old values. NOTES.txt (`templates/NOTES.txt:18`) and helm.md:279 promise "Configuration changes are applied with `helm upgrade`; no reinstall". Today the only way out is a new database.
- **Comparable:** Velero, Loki and Prometheus Operator apply changed limits on rollout. Kubernetes ResourceQuota edits take effect immediately.
- **Origin:** agent (ADR-197/226 root-backing qualification). The maintainer requirement is only "protection against capture storms and storage exhaustion".
- **ADR-330:** D7 (per-workload counters, no prepaid ledgers) and D13 remove the cause. Implementation gap.
- **Fix:** store quotas as ordinary rows updated from values or CRDs on every reconcile. A lower limit stops new admissions; it never invalidates existing evidence. Until then, fail `setup` loudly with the diff instead of logging and continuing.

### U-02 Connector wedges at `identity` after one hour (homelab outage)
- `internal/bootstrap/hub_api_regional_offer.go:121-135` writes the offer only if empty. `internal/bootstrap/capacity_qualification.go:144,163` sets the connector backing `ValidUntil = first hub-api start + federation.connector.validSeconds` (min 3600). `examples/helm/context-trial-profile.yaml:123`.
- **Effect:** any connector restart more than an hour after the first hub-api start waits forever. The homelab README "Known issue" and `source.json` qualification record this outage. Nothing renews the offer, and no documented recovery exists.
- **Comparable:** OCM and kubelet agents re-register at any time. Argo CD cluster Secrets do not expire.
- **Origin:** agent.
- **ADR-330:** D3 and D7 remove backing validity and prepaid connector accounts, and ADR-334 removes the offer. Implementation gap. Fix it on main now because it breaks running installs.
- **Fix (interim):** rewrite the offer whenever its backing is within its validity margin, or derive `ValidUntil` per enrollment. **Fix (final):** delete the backing and offer entirely.

### U-03 Pre-existing AccessBindings wedge the permission reconciler
- `internal/application/configuration/reconciler.go:423-426`: `!fence.Initialized && len(snapshot.Bindings) > 0 && Review == nil → ErrDenied`. Chart `values.yaml:283-285` (`hub.hub-worker.permission.review`).
- **Effect:** this hits GitOps users whose repo applies AccessBindings with or before the chart, and any reinstall after `helm uninstall` (CRDs and bindings are kept). The hub-worker never accepts permissions, so nobody gets access. Recovery needs an "administrator-created initial review ConfigMap" with an undocumented exact shape.
- **Comparable:** RBAC, Kyverno and Argo CD AppProjects take effect from whatever objects exist.
- **Origin:** agent ("historical-value review").
- **ADR-330:** D11 and D13 ("no historical-value review") remove it. Implementation gap.
- **Fix:** accept the current list on first start, as on every later start. Delete the review input and its value.

### U-04 UUIDs and UIDs typed by humans throughout
- Console:
  - `web/src/capture/CaptureWorkspace.tsx:174` ("Registered cluster UUID")
  - `web/src/capacity/CapacityWorkspace.tsx:53`
  - `web/src/processing/ProcessingDiscovery.tsx:109-116` (Case ID, Cluster ID, Namespace UID, Workload UID)
  - `web/src/policy/PolicyWorkspace.tsx:103` (paste the approved grant UUID)
  - `web/src/processing/ProcessingErasureStatus.tsx:75`
- CRDs:
  - `charts/asservat/crds/accessbindings.yaml`: `workloads[].uid` is required (`api/v1alpha1/permissions.go:11-15`).
  - `evidencebudgetpolicies.yaml:57` (`scope.clusterID` uuid)
  - `evidenceretentionpolicies.yaml:314`
  - `permissionsources.yaml:65`
  - `debugpolicies.yaml:485` (`grantRef` uuid; `internal/application/capture/policy_compile.go:172-178`)
- Values:
  - `values.yaml:113` (`clusters[].clusterID`: "a lowercase UUID you choose (uuidgen)")
  - Keycloak/OIDC subject IDs repeated three times in the homelab values (`values.yaml.gotmpl:21-31`)
- MCP: `request_policy_grant` requires `policy_uid`.
- **Effect:** users copy IDs out of kubectl or Secrets. A GitOps AccessBinding narrowed to a workload cannot be written ahead of time, and it silently stops matching when the Deployment is recreated with a new UID.
- **Comparable:** Argo CD, Grafana and Kubeshark use cluster names, namespace and workload names, and pickers.
- **Origin:** agent. Stable IdP group IDs are in the spec (D11), but cluster, namespace and workload UIDs are not maintainer requirements.
- **ADR-330:** not removed. D11 keeps group IDs; cluster IDs and UID references remain in contracts.
- **Fix:** name clusters by `clusters[].name` (generate the UUID internally) and accept names in every CRD and form. Give the console a cluster/namespace/workload picker backed by `list_targets`. Use `workloads[].name` only, resolving the UID at decision time. Attach a grant automatically when its approval is decided, with no paste step.

### U-05 No usable defaults: only the trial profile works, and it is a toy
- `values.yaml:131` (`capacity: {}`) and `:136` (`retention: {}`) leave collection off. helm.md:300-305: "Combined mode requires `federation.connector` and `capacity.backup`, which the trial profile supplies."
- `examples/helm/context-trial-profile.yaml` is ~130 lines of footprints, WAL bytes, key attempts, backup horizons and lanes:
  - `:107` evidence retention default 300 s, max 3600 s
  - `:16` `maxSessions: 8` installation-wide
  - `:34` `accounts: 2`
  - `:33` `namespaceKeys: [asservat-trial]`, so only namespaces labelled `asservat-trial=true` are capturable
- The homelab runs exactly this profile.
- **Effect:** a real install keeps evidence for 5 minutes and caps the whole organisation at 8 browser sessions and 2 workloads with evidence. Production numbers cannot be derived, because the values are arithmetic inputs, not product limits (`_helpers.tpl:251-252` makes operators satisfy `retainedSeconds ≥ validSeconds + 2*horizon + 3*cleanup + proof + 60`).
- **Comparable:** Loki, Pyroscope and Sentry Helm charts work with defaults and expose a handful of retention and limit knobs.
- **Origin:** agent. Administrator-enforced maximum retention and storm/exhaustion protection are maintainer requirements, and a few knobs satisfy them.
- **ADR-330:** D7 removes the WAL/backup prepayment and second ledgers; D12 simplifies retention. Implementation gap.
- **Fix:** defaults usable out of the box: retention default 7 days with an administrator maximum, a per-workload byte/object quota, a namespace quota, a burst limit and an opt-out namespace label (not opt-in). Delete the footprint, WAL, keyAttempts, backup and lanes values.

### U-06 Mandatory explicit CA bundles even for public CAs
- `charts/asservat/templates/hub-api-deployment.yaml:12-13` fails without `identity.providerRootsPEM`. External PostgreSQL, S3 and OpenBao all need `rootsPEM` (helm.md:74-76). `SystemCertPool` is used nowhere in `internal/`.
- **Effect:** the homelab vendors `public/letsencrypt-roots.pem` into values. Every operator must find and maintain their IdP's root chain, and a CA change breaks login until values are updated.
- **Comparable:** Grafana, Argo CD and cert-manager use system roots, with an optional extra CA bundle.
- **Origin:** agent.
- **ADR-330:** not addressed.
- **Fix:** default to system roots plus an optional `caBundle`. Pinning stays available as an option.

### U-07 Bundled Keycloak needs two install passes and jq extraction
- helm.md:148-161; `internal/bootstrap/small_keycloak_prepare.go`.
- **Effect:** install with a placeholder, read the group IDs from `<name>-keycloak-state` with base64/jq, edit `identity.eligibleGroups`, `fleet.groups` and `processingOperators`, then upgrade.
- **Comparable:** Argo CD and Dex, or Grafana with bundled auth, work in one pass.
- **Origin:** agent.
- **ADR-330:** no.
- **Fix:** the secrets hook generates the group IDs before the realm import, and hub-api reads them from the Secret. Values reference bundled groups by name (`asservat-users`).

### U-08 Four separate access lists for one person
- `identity.eligibleSubjects/eligibleGroups` are required non-empty (`internal/domain/identity/identity.go:186`). On top of those come `identity.processingOperators` (`{clientID, issuer, kind, id}`), `fleet.subjects/groups` plus `fleet.issuer` and `fleet.clients` (which duplicate `identity.issuer/clientID`), AccessBindings, and `identity.clients[].classQualified`. See the homelab values, `values.yaml.gotmpl:15-37`.
- **Effect:** granting one engineer access means writing their subject ID in 3-4 places plus an AccessBinding. Missing one gives a different refusal each time.
- **Comparable:** Argo CD uses one RBAC policy, and Grafana uses org roles plus team permissions.
- **Origin:** mixed. The maintainer requires Kubernetes-only permission configuration and automated permission management, which AccessBindings satisfy. The parallel eligibility, fleet and processing lists are agent-added.
- **ADR-330:** not removed.
- **Fix:** sign-in eligibility = any authenticated user of the configured issuer/client (optionally one group). Fleet and processing-operator rights become AccessRoles bound through AccessBindings or PermissionSources in the release namespace. `fleet.issuer/clients` are derived from `identity`.

### U-09 Post-install "processing initialization" API call
- `internal/transport/browser/processing_scope.go:72` (`initialize_processing`); helm.md:84-85; `test/integration/installed_identity_test.go:380`.
- **Effect:** after install, a listed processing operator must POST `/api/v1/processing/changes {"action":"initialize_processing"}` before any capture can keep evidence. Without it, captures fail with `ProcessingCoverageUnavailable`.
- **Comparable:** Sentry and Grafana have no "initialize" step.
- **Origin:** agent. The privacy inventory itself (processors) is an optional maintainer feature, but this activation step is not.
- **ADR-330:** no.
- **Fix:** setup initializes processing from values. The operator role remains only for later restriction or erasure.

### U-10 External OpenBao and S3: manual multi-object provisioning
- External OpenBao (helm.md:233-276): 2 transit mounts with 7 keys named with `<inst>` (installation UUID without dashes, read from `<name>-ids`), 3 PKI mounts with 6 roles, KV, 2 Kubernetes auth mounts, and ~18 ACL policies/roles. Path "not qualified yet".
- External S3 (helm.md:216-228): 9-11 hand-made `<name>-s3-<principal>` Secrets with per-prefix grants.
- External PostgreSQL: ≥117 connections (helm.md:209-210), because one MaxConns=1 pool per role (`internal/bootstrap/service_inputs.go:141`, `internal/contracts/public_runtime_compartments.go:7`).
- **Comparable:**
  - Loki and Tempo take one bucket plus one credential.
  - Vault-using tools (cert-manager, external-secrets) need one role.
  - Argo CD and Grafana need a 10-20 connection pool.
- **Origin:** maintainer for "no unencrypted managed evidence storage" and "OpenBao/static-key options". The per-purpose split is agent-added.
- **ADR-330:** D3 (one installation CA, no PKI per purpose) and D6 (audit as DB rows: no audit transit keys or audit S3 principals) remove most of it. Implementation gap.
- **Fix:**
  - OpenBao: one transit key for envelope wrap/unwrap, with setup creating it if the token permits.
  - S3: one evidence-bucket credential for the hub and one write-only credential per region.
  - SQL: one or two pooled logins sized like normal apps.

### U-11 Capture review expires in 2 minutes; the 5-minute session limit leads to "uncertain" errors
- `values.yaml:244` (`previewSeconds: 120`); `internal/application/capture/context_investigation.go:149` (lifetime ≤ 5 min); `internal/transport/presentation/context_operations.go:337-347`:
  - `PreviewExpired`
  - `AcquisitionUncertain` ("check its status before starting a new investigation")
  - `AcquisitionNotStarted` ("continue_acquisition: true")
  - `Conflict`
  - `ReviewChanged` ("resolve the original request before reviewing a replacement")
- **Effect:** a human who reads the plan for more than 2 minutes, or asks a colleague first, gets `PreviewExpired`. Several error paths tell users to resolve hidden state with a preview ID and request key.
- **Comparable:** `kubectl apply --dry-run` followed by apply, and Terraform plan/apply with a plan file, have no server-side expiry.
- **Origin:** agent.
- **ADR-330:** D7 and D9 remove it (stateless previews, idempotency keys). Implementation gap (implementation-progress.md:16-19).
- **Fix:** implement D9. Until then, raise `previewSeconds` to ≥1800 by default.

### U-12 Downloads must finish within 5 minutes and use a Job per download
- `values.yaml:247-261` (`downloadPlan.durationSeconds: 300`, `requestLimit: 4`, `downloadConcurrency: 4`, `downloadsPerIdentity: 2`); `internal/application/evidence/context_download_control.go:273` (session deadline = now + plan.Duration; ADR-312 never extends it); `templates/download-worker.yaml` (a Job per download).
- **Effect:**
  - At the measured 1.2 MiB/s (ADR-330 complexity gate), the 256 MiB output limit needs about 3.5 minutes. A slower link, or a pause in Wireshark's "save", kills the download, and only 4 resumes are allowed.
  - The whole installation allows 4 concurrent downloads.
  - Every download waits for Job scheduling.
- **Comparable:** S3 presigned URLs last up to 7 days. Sentry and Grafana stream directly.
- **Origin:** maintainer for native download with authentication and audit. The 5-minute deadline, 4-request cap and Job per download are agent-added.
- **ADR-330:** D4 (long-running readers) and D5 remove the Job. The deadline value is not addressed.
- **Fix:** D4 readers. Session deadline = min(access-until, 24 h). Resume without a request cap (ranges are idempotent). Concurrency from reader replicas.

### U-13 Upgrades take the console down; hub-worker cannot be replicated
- `templates/hub-api-deployment.yaml:23` (`strategy: Recreate`), `templates/hub-worker-deployment.yaml:16-17` (Recreate), `values.schema.json` `hub.hub-worker.replicas maximum 1`, `templates/connector.yaml:288-291` (replicas 1, Recreate).
- **Effect:**
  - Every `helm upgrade` and every values change (checksum annotation) stops all hub-api Pods first, so the console and MCP go down.
  - The homelab upgrade restarted hub-api 3 times (`source.json`: "recovery-proof-interval expired while the new hub-worker waited for the scheduling lease"), so hub-api's liveness depends on hub-worker's lease handover.
  - A hub-worker or connector node failure stops permission reconciliation and collection until rescheduling.
- **Comparable:** Argo CD, Grafana and Loki use RollingUpdate with leader election for singletons.
- **Origin:** agent.
- **ADR-330:** D2 and D3 (no per-process enrollment or routing proofs) remove the reasons. Implementation gap.
- **Fix:** RollingUpdate for hub-api. hub-worker with replicas ≥2 and lease-based leader election, with no hub-api dependency on the hub-worker lease. Connector with 2 replicas, one holding the hub connection.

### U-14 Groups need a custom attribute mapper; the standard `groups` claim is ignored
- helm.md:177-181,189-194 (`asservat_group_id` user-attribute mapper to the `asservat_groups` claim, the `evidence:*` default client scopes); `internal/domain/identity/identity.go:186,229`: `GroupMaxAge ≤ 5 min` after token `iat`.
- **Effect:**
  - The IdP admin must give every group an extra attribute and keep it unchanged.
  - Non-Keycloak IdPs (Entra, Okta, Google, Authentik) need custom claim engineering.
  - Group-based access lapses 5 minutes after token issue unless the client refreshes.
- **Comparable:** Argo CD and Grafana read a configurable `groups` claim (name or ID) with no custom attribute.
- **Origin:** agent (ADR-053). AGENTS.md says "administrator-controlled stable group IDs", but only in the implementation notes, not under "Authority and invariants".
- **ADR-330:** D11 keeps "stable IdP group IDs".
- **Fix:** configurable `groupsClaim` (default `groups`) accepting whatever the IdP emits. The stable-ID attribute stays an option. Group freshness = token lifetime.

---

## Medium

### U-15 Hard cap of 15 joined clusters; namespace refresh silently stops after 8
- `internal/bootstrap/hub_api_remote_clusters.go:31-46` (`remoteClusterLimit = 15`, values schema `clusters maxItems 15`, each `standby`/`captures` ≤16). `internal/application/configuration/reconciler.go:85-87,232-233`: `MaxRemoteNamespaceClusters = 8`, sorted by UUID, and later clusters are truncated ("stay unavailable") with no error. `:108-109,177-178`: `MaxWorkloadSelections = 32`, also silently truncated.
- **Effect:** the ninth joined cluster gets no namespace metadata, so its namespace-selector permission sources are indeterminate and nothing tells the operator.
- **Comparable:** Argo CD, OCM and Rancher manage hundreds of clusters.
- **Origin:** agent.
- **ADR-330:** D1 (pushed state) removes the polling that motivated the caps. Implementation gap.
- **Fix:** remove the caps with pushes. Until then, refuse values with more than 8 clusters, or log and report the condition per cluster.

### U-16 One concurrent capture per cluster by default
- `values.yaml:117,243` (`captures: 1`, `standby: 2`); schema maximum 16.
- **Effect:** two engineers investigating different incidents on the same cluster queue or fail with `CapacityUnavailable`.
- **Comparable:** Kubeshark and Pyroscope allow many concurrent sessions.
- **Origin:** agent ("standby connections").
- **ADR-330:** D2 (no standby socket pools) removes `standby`.
- **Fix:** limit concurrency by per-workload and per-node quotas (maintainer storm protection), not a per-cluster constant. Default ≥8.

### U-17 Installation-wide session cap; hard-coded 10 sessions per user
- `internal/adapters/postgres/browser.go:119-120,175-183` (`n >= MaxLogins/MaxSessions`, and a literal `n >= 10` per subject); defaults `values.yaml:44-46` (64 logins, 256 sessions; trial 8).
- **Effect:** at 256 live sessions everyone gets HTTP 429 at login until sessions expire (8 h). A user with more than 10 browsers or tabs that reauthenticate is locked out.
- **Comparable:** Grafana and Argo CD have no installation-wide session cap.
- **Origin:** agent.
- **ADR-330:** no.
- **Fix:** evict the oldest session of the same user instead of refusing, and drop the installation cap (or make it ≥10⁵).

### U-18 DebugPolicies: max 16 per cluster, exit detector only, approval by pasting a UUID
- `internal/domain/capture/policy_trigger.go:19-28` (`MaxActivePoliciesPerCluster = 16` "bounds polling queries", `TriggerPollInterval = 15s`, `WorkloadTriggerInterval = 5min`, burst 2); `policy_compile.go:166-179` ("unsupported in this release (ADR-228)" for every other key).
- `web/src/policy/PolicyWorkspace.tsx:90-104`: request approval, then paste the grant UUID into "Attach approved grant".
- MCP `activate_policy` is needed separately from `kubectl apply`.
- **Effect:** a team with 20 services cannot watch them all. Applying a DebugPolicy via GitOps does nothing until a human activates it and then attaches a pasted grant ID.
- **Comparable:** Kyverno policies and PrometheusRules take effect on apply.
- **Origin:** expiring policy grants for automatic intrusive actions are maintainer requirements. Activation, pasting and the polling cap are agent-added. The per-workload trigger budget implements maintainer storm protection, but should be a policy field.
- **ADR-330:** D1 (watch events) removes the polling cap; D10 removes signed submissions and intent versions.
- **Fix:** watch-based triggers with no per-cluster cap. A policy is active when applied and its grant is approved. Approval links to the policy by name, with no attach step.

### U-19 Short capture windows
- `internal/domain/collector/channel.go:122` (`MaxPacketCaptureDuration = 5min`); `internal/domain/artifact/recording.go:36-37` (syscall 60 s, recording 5 min); `internal/application/planning/recorder.go:359,524` (syscall after ≤60 s, raw after ≤15 s); `internal/domain/targets/live_manual_source.go:41` (manual live source ≤5 min); `internal/domain/live/watch.go:21-23` (16 sources, 100 rows).
- **Effect:** intermittent bugs (every ~20 min) cannot be captured in one manual session, so users must repeat preview, approval and request.
- **Comparable:** Kubeshark runs ongoing captures; `tcpdump -G` rotates indefinitely.
- **Origin:** maintainer for "segmented rings" and "bounded windows" (bounded is required, but the values are not).
- **ADR-330:** no.
- **Fix:** make the durations administrator ceilings in budget policies (default ≥1 h for packets with ring segmentation), not code constants.

### U-20 `federation.connector` fixed at first install
- `charts/asservat/templates/_hubapi.tpl:115` ("fixed at the first install"); helm.md:338-339; `_helpers.tpl:251-252` arithmetic.
- **Effect:** the operator must guess on day one how many clusters they will ever join (`profiles`). Joining one more later needs a new installation.
- **Origin:** agent.
- **ADR-330:** D7 (no prepaid accounts) removes it, and ADR-334 replaces the connector identity. Implementation gap.
- **Fix:** delete the `federation.connector` values.

### U-21 Connector restarts consume finite enrollment records
- `internal/contracts/regional_offer.go:92-97` (`RegionalRetainedProcesses = 8`, `RegionalServingSlots = 2`); `examples/helm/context-trial-profile.yaml` `federation.connector {accounts: 1, recordsPerAccount: 96, retainedSeconds: 4000}`; enforcement in `migrations/00051_connector_retirement.sql:154-397`.
- **Effect (from code reading, not observed):** each connector process enrollment holds a ticket and record until `retainedSeconds`. A crash-looping connector or a busy rollout day can exhaust them and block enrollment for over an hour.
- **Comparable:** kubelets and agents reconnect without limit.
- **Origin:** agent.
- **ADR-330:** D3 removes per-process enrollment. Implementation gap.
- **Fix:** delete it together with per-process enrollment.

### U-22 Kubernetes ≥ 1.35 required
- `charts/asservat/Chart.yaml:6` (`kubeVersion: ">=1.35.0-0"`); the reason is ADR-056's resource-version ordering for retention watch watermarks.
- **Effect:** many managed clusters (EKS and GKE stable channels, OpenShift) lag 2-3 minor versions, so the chart refuses to install there.
- **Comparable:** cert-manager and Argo CD support N-3 or more.
- **Origin:** agent.
- **ADR-330:** D12 removes watch watermarks. Implementation gap.
- **Fix:** lower `kubeVersion` to the oldest version with the features actually used (ValidatingAdmissionPolicy GA, 1.30).

### U-23 PermissionSource needs two applies to preview
- `internal/transport/presentation/access_preview_operations.go:181` ("apply the source with enabled: false first, then preview enabling it").
- **Effect:** an operator who wants to see the effect of a new namespace-selector source has to apply it twice.
- **Comparable:** `kubectl apply --dry-run=server` and `kubectl auth can-i` answer in one step.
- **Origin:** agent.
- **ADR-330:** D1 and D11 (no assignment continuity) cover the cause indirectly.
- **Fix:** evaluate the selector against the current namespace informer cache in the preview itself.

### U-24 1,024 AccessBindings per cluster, shared by all namespaces
- `internal/domain/configuration/remote_bindings.go:13-15,41`; `internal/adapters/kubernetes/access_binding_delivery.go:56`; helm.md:450-454.
- **Effect:** a cluster with more than 1,024 bindings (300 namespaces × 4 roles) fails the whole delivery or LIST, and one namespace can exhaust it for all the others. The docs tell operators to add ResourceQuotas to compensate.
- **Comparable:** RBAC has no such cap.
- **Origin:** agent.
- **ADR-330:** no.
- **Fix:** raise to ≥10⁵ with paged LIST and an informer. Refuse only the offending namespace's bindings, never the cluster's.

### U-25 External SQL requires TLS 1.3 and 117 connections; no plain in-cluster option
- helm.md:201-210; `internal/adapters/postgres/runtime_roles.go:81` (`MinVersion < tls.VersionTLS13` → invalid).
- **Effect:** older managed PostgreSQL (TLS 1.2 only) and small shared servers (max_connections 100) cannot be used.
- **Comparable:** Grafana, Argo CD and Sentry accept TLS 1.2 and a normal pool.
- **Origin:** agent.
- **ADR-330:** no.
- **Fix:** TLS 1.2+ with verification. Pool size per component as a value, with a total default ≤30.

### U-26 "Uncertain" and never-refunded charges surface to users
- Code comments: `internal/application/execution/context.go:38` ("Unknown starts stay spent"), `internal/adapters/postgres/download.go:433`, `context_key_unwraps.go:28`, `application/evidence/context_download.go:39`, `application/privacy/streaming.go:183`, `application/capture/cancellation.go:36`, and many more.
- **Effect:** after a transient error, users see `AcquisitionUncertain` or `CapacityUnavailable` while quota stays consumed until retention (hours). On small quotas (U-05) a few network blips exhaust a workload.
- **Comparable:** Stripe-style idempotency resolves unknown outcomes by lookup.
- **Origin:** agent.
- **ADR-330:** D7 removes it. Implementation gap.
- **Fix:** D7.

### U-27 Console polls; MCP clients are told to re-call
- implementation-progress.md:16-19 (`retry_after_seconds`, no SSE); `hub.publisher.pollSeconds: 2` (`values.yaml:344`).
- **Effect:** status changes appear late in the browser. MCP agents loop, burning tokens and rate limits (`mcpPerIdentity: 2`, `values.yaml:246`).
- **Origin:** agent.
- **ADR-330:** D1 removes it. Implementation gap.
- **Fix:** D1 (SSE and ≤30 s server-side waits).

### U-28 Restore/rollback path undocumented; recovery fence needs a non-existent protocol
- AGENTS.md ADR-096/098 notes ("Supported restore must fence service and change the PostgreSQL process/database incarnation … independent restart/restore protocol still pending"); helm.md:282-283 ("an older image refuses a newer schema", forward-only); helm.md:511-513 ("Never delete generated Secrets or retained PVCs to clear an error").
- **Effect:** an operator who restores PostgreSQL from pgBackRest after an incident has no documented way back to a working installation. Helm rollback is not possible after any migration.
- **Comparable:** Argo CD, Grafana and Sentry document backup and restore; migrations are usually backward compatible for one minor version.
- **Origin:** agent (installation-witness and incarnation fence).
- **ADR-330:** D13 removes the installer-era machinery. Restore is not specified.
- **Fix:** document `pg_restore` plus `helm upgrade` as the restore path, with no incarnation fence beyond schema version. Keep migrations expand/contract so N-1 images run on schema N.

### U-29 Collection gated behind a host file on every node
- `values.yaml:193-198`, helm.md:470-490 (`/etc/asservat-disposable-host`, "test hosts only").
- **Effect:** packet, syscall and dump collection (the product's core) cannot be used on any real cluster.
- **Origin:** maintainer ("Do not enable collection for users before the slice's authority, custody and privacy requirements pass"; "Never enable a privileged collector on this workstation").
- **ADR-330:** no.
- **Fix:** keep the gate until the collector is qualified, but track qualification as the release blocker. Replace the file with an ordinary `collector.enabled` plus a node selector once qualified, as Kubeshark and Pixie do.

---

## Low

### U-30 Key versions capped at 16
- `internal/adapters/kms/local_keys.go:24` (`maxLocalVersions = 16`), additive rotation (ADR-067).
- **Effect:** after 16 rotations the static-key backend cannot rotate again without retiring versions, and retirement "remains pending".
- **Origin:** agent. **ADR-330:** no.
- **Fix:** allow retiring versions whose ciphertexts are gone, or raise the cap.

### U-31 CRDs are not upgraded by Helm; a separate `kubectl apply` is needed every time
- helm.md:122-131; homelab presync hook.
- **Comparable:** cert-manager offers `crds.enabled` (CRDs as templates with `keep`).
- **Origin:** agent. **ADR-330:** no.
- **Fix:** a templated-CRD option with `helm.sh/resource-policy: keep`.

### U-32 Mandatory `reason` fields
- AccessBinding CRD requires `spec.reason`. MCP requires `reason` on `request_raw_access`, `decide_review` and `create_share` (`specs/contracts/implemented/mcp-tools.json`).
- **Comparable:** RoleBindings have no reason. Approvals in Argo CD and GitLab allow an optional comment.
- **Origin:** raw approval is maintainer ("one bounded independent approval"); the mandatory free-text reason is agent-added.
- **ADR-330:** D8 keeps reasons as rows.
- **Fix:** make the reason optional, except where an approver must see one (the raw-access request).

### U-33 Values carry legacy installer names and non-functional knobs
- `values.yaml:128-140` ("the former bootstrap.continuation.public.capacity", "former installer DTO field names"), `hub.hub-api.retentionTopologies` (schema `maxItems 0`), `hub.key-service.downloads.retentionTopologies`, `hub.publisher.retentionTopologies`, `hub.hub-worker.permission.statusUsers`, `region.executor.capacityAudience`, `clusterObservationAudience`.
- **Effect:** operators read about concepts they cannot use.
- **Origin:** agent. **ADR-330:** D13. Implementation gap.
- **Fix:** delete them with their code.

### U-34 Every context artifact is 4 KiB max; a case holds max 100 artifacts; max 10 open previews per user
- `internal/domain/artifact/context.go:6`, `internal/domain/catalog/context.go:17`, `internal/domain/capture/preview.go:33`.
- **Effect:** large pod-status snapshots (many containers or events) are rejected, and long incidents hit the per-case cap.
- **Origin:** agent. **ADR-330:** D9 removes preview handles.
- **Fix:** size limits as configurable ceilings (≥1 MiB for context) and no per-case artifact cap beyond quota.

### U-35 Keycloak bundled realm cannot be `master`; MCP redirect URIs ≤32
- `internal/bootstrap/small_keycloak_prepare.go:29`.
- **Effect:** minor; the homelab's existing realm `master` works only with an external provider.
- **Origin:** agent. **ADR-330:** no.
- **Fix:** none needed beyond a clear message.

### U-36 Setup waits only 5 minutes per unreachable provider, then the Job fails
- `internal/bootstrap/setup.go:44` (`setupRetry = 5 * time.Minute`).
- **Effect:** on a cold cluster where the PVC or OpenBao takes longer, the setup Job fails and the operator reruns `helm upgrade`. Workloads stay in `wait-schema` meanwhile.
- **Comparable:** Argo CD and Sentry migration Jobs retry with `backoffLimit` until ready.
- **Origin:** agent. **ADR-330:** no.
- **Fix:** retry indefinitely with backoff, bounded by the Job's `activeDeadlineSeconds`, which operators can tune.

---

## Not reported (verified as not friction)
- Download/projection cleanup selects ≤16 rows per tick, but the SQL uses `LIMIT 16` (`migrations/queries/download_workers.sql:117`), so it does not wedge.
- `maxProcesses = 8192` (`internal/adapters/linux/probe.go:26`) is a /proc scan bound, which is harmless.
- Generated Secrets created once and never rotated: standard (Argo CD admin secret, Grafana). Rotation by `existingSecret` override is acceptable.
