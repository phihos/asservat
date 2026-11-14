# Operator friction audit: install, upgrade, rollback, backup/restore, day-2

Worktree `/home/phil/Projekte/asservat-ux` at `5d4667715` (ADR-330). Read-only audit.
Known items excluded per the brief: join Secrets, bootstrap records, the four
connector endpoints, image-digest pinning (ADR-334).

## What a typical operator must set, generate or size today

To get one working `mode: combined` install with all services bundled, the operator must:

1. Build two images from source (product and a custom PostgreSQL/pgBackRest image), push both and copy two registry digests.
2. Create the namespace by hand and label it PSA `restricted`. `--create-namespace` in the README does not label it.
3. Issue two TLS Secrets by hand (console and Keycloak) and pass the CA as a file.
4. `kubectl apply` the CRDs by hand before every install or upgrade.
5. Write roughly 25 site values. Every provider defaults to `external`, so `helm install` with defaults fails.
6. Supply around 110 lines of capacity, retention and connector byte/WAL/row arithmetic (`context-trial-profile.yaml`). It has no defaults, and its own header says "NOT measured". Combined mode refuses to render without it.
7. Install with a placeholder `processingOperators` entry. Then read the Keycloak group UUIDs from a Secret with `jq`, edit values, run `helm upgrade` a second time and wait for a second setup Job.
8. Sign in to the Keycloak admin UI with a password read from a Secret, then create users and assign groups.
9. Sign in to the console, open `/processing` and click **Refresh processing rules** and then **Initialize processing**. Captures stay unavailable until this is done.
10. Label each application namespace for the budget policy. Write an AccessBinding that carries the Deployment's UID and a mandatory `reason`.

Comparable charts (Argo CD, Grafana, Loki, cert-manager, Kyverno) install with defaults plus a hostname/TLS choice. They print the admin password in NOTES, and they reach a first useful action without any post-install console step.

---

## Findings

### OPS-01: Bundled Keycloak settings are frozen at first install; changing them breaks `helm upgrade` (high)
- **Where:** `internal/bootstrap/small_keycloak_prepare.go:99-105` (stored settings JSON compared byte-for-byte), `internal/bootstrap/small_keycloak_state.go:59-64`, `charts/asservat/templates/secrets-job.yaml:31-38`, `specs/deployment-profiles.md:11`.
- **Today:** The `secrets` hook writes an immutable `<name>-keycloak-state` Secret containing `hostname`, `origin`, `realm`, client IDs, `mcpRedirectURIs` and the `processingOperators` toggle. Later changes to any of these do not apply. The retained Secret then fails validation, so the hook returns `Unavailable` and every following `helm upgrade` fails. Keycloak also uses `--import-realm`, which skips an existing realm. The only escape is deleting the Secret. Then `DatabaseStateExists` refuses to recreate it, so the install wedges.
- **Why friction:** Moving the console to a new hostname, adding an MCP redirect URI or enabling the operator group is a routine values change. The Keycloak and Argo CD charts reconcile realm and client settings on upgrade, for example through keycloak-config-cli or the Keycloak operator's `KeycloakRealmImport`. No comparable chart makes the IdP hostname permanent.
- **Trace:** The maintainer chose bundled Keycloak (ADR-063/326) and stable group IDs. Freezing the redirect URIs, origin and hostname was agent-added.
- **Fix:** Keep only the generated secrets immutable (admin password, client secret, group UUIDs). Reconcile the realm's clients, redirect URIs and scopes on every setup run through the Keycloak admin REST API, idempotently, with the bootstrap admin credential. Stable group IDs are preserved because the UUIDs stay in the Secret.

### OPS-02: A bundled install takes two passes, and the example claims an automatic step that does not exist (high)
- **Where:** `docs/installation/helm.md:136-163`, `docs/installation/small-profile.md:61-80,127-140`, `examples/helm/small-profile-values.yaml:480,488` ("Product adds the original generated users-group UUID"), `charts/asservat/templates/_hubapi.tpl:152,182`. Only `internal/bootstrap/small_keycloak_prepare.go` reads `users-group-id`; nothing else consumes it.
- **Today:**
  - The operator installs with a fake `processingOperators` entry (`kind: User, id: 00000000-…`), because `_hubapi.tpl:182` fails on an empty list.
  - They then read two UUIDs out of a Secret with `jq`, paste them into `identity.eligibleGroups`, `fleet.groups` and `processingOperators`, and run `helm upgrade` again.
  - The example file says the product adds the users group itself. It does not, so following the example leaves nobody eligible to sign in.
- **Why friction:** A bundled IdP exists to remove this kind of wiring. Grafana and Argo CD with bundled Dex or Keycloak derive group mappings from names the chart itself created.
- **Trace:** Stable group IDs are a maintainer requirement. The second pass and the mandatory operator list are agent-added.
- **Fix:** When `services.identity.provider: keycloak`, the hub reads `users-group-id` and the operators group ID from `<name>-keycloak-state` at startup. It treats them as default `eligibleGroups`, `fleet.groups` and `processingOperators`, and explicit values are added on top. Drop the `processingOperators` render failure for the bundled provider. Fix the example comment.

### OPS-03: Combined mode requires ~110 lines of unmeasured capacity/WAL/row arithmetic, with no defaults (high)
- **Where:** `charts/asservat/values.yaml:128-140` (`capacity: {}`, `retention: {}`, `federation` commented out, all described as "former installer DTO field names"), `values.schema.json` `installerCapacity`. It requires 15 keys, including `footprints.*.rowBytes/transitionWALBytes`, `metadata.recordWALBytes`, `envelope.walBytes`, `backends[]`, `lanes.*` and `purgeLeases`. Also `installerConnector` (8 keys), `_hubapi.tpl:111-112`, `_helpers.tpl:248-253`, and the whole of `examples/helm/context-trial-profile.yaml`.
- **Today:**
  - Combined mode or any joined cluster fails to render without `capacity.backup` and `federation.connector`.
  - The operator must copy a trial file whose header says "NOT measured end-to-end".
  - They must also satisfy `retainedSeconds >= validSeconds + 2*horizon + 3*cleanupBudget + proofWindow + 60` by hand.
  - None of these fields is documented beyond "see values.yaml". `capacity.md:110` promises "Defaults come from one reusable budget profile; ordinary users need no quota YAML."
- **Why friction:** Loki, Mimir and Prometheus ship working defaults and expose a few human-sized knobs: retention period, storage size and per-tenant limits. No comparable chart asks operators to size PostgreSQL WAL bytes per row-transition.
- **Trace:** The maintainer required storm protection, cross-workload storage-exhaustion protection and administrator-enforced maximum retention. The internal row/WAL accounting surfaced as values is agent-added.
- **Fix:**
  - Ship defaults derived from three human inputs: the evidence pool size (`EvidenceStoragePool.capacity`), the number of protected workloads and the retention maximum.
  - Compute footprints, WAL, lanes and `retainedSeconds` in Go from those inputs and the PVC sizes the chart already knows.
  - Move the internal fields to an undocumented `advanced` block, or remove them.
  - Make `capacity`, `retention` and `federation.connector` default on in `combined` mode.

### OPS-04: `federation.connector.profiles` is fixed at first install; joining one more cluster than planned needs a reinstall (high)
- **Where:** `docs/installation/helm.md:338-339`, `charts/asservat/templates/_hubapi.tpl:115`, `docs/decisions/331-remote-cluster-join.md:149-150`.
- **Today:** The operator has to predict the final cluster count at first install. Exceeding it means reinstalling the hub, which loses or orphans SQL state, because the schema and Secrets are retained and only move forward.
- **Why friction:** Argo CD, OCM and Rancher add clusters at any time, and no comparable fleet tool fixes a cluster count at install.
- **Trace:** Agent-added (a WAL/row prepaid-backing calculation).
- **Fix:** Make the connector backing resizable on `helm upgrade`. Setup recomputes the backing and accepts growth. Shrinking below current use is refused, as the spec's own resize rule in `capacity.md:68` already handles for pools. At minimum, derive `profiles` from `len(clusters)+1` plus headroom so nobody types it.

### OPS-05: Hard cap of 15 joined clusters, and every join requires editing the hub's values (high)
- **Where:** `charts/asservat/values.schema.json:400` (`clusters.maxItems: 15`), `charts/asservat/values.yaml:108-117`, `fleet.maxClusters` default 1.
- **Today:** Each new workload cluster needs a `clusters[]` entry on the hub, a hand-generated `clusterID` UUID (`uuidgen`) and a hub `helm upgrade`. A 16th cluster is rejected by the schema. A failed first enrollment burns the `clusterID`: "re-joining needs a new clusterID" (ADR-331:147). Every budget policy naming the old ID then has to be edited.
- **Why friction:** OCM, Argo CD and Karmada register from the spoke side. Their IDs are generated (the cluster's `kube-system` UID or a server-side UUID), and their fleets reach hundreds of clusters.
- **Trace:** Agent-added. This partly overlaps ADR-334's join redesign. The 15-item cap and hand-chosen UUIDs are separate and still apply.
- **Fix:** Generate the cluster ID server-side, or use the `kube-system` namespace UID. Let budget policies select clusters by `name`. Raise the cap to the real limit (`maxClusters` ≤ 1024 already exists). Allow re-enrolling the same cluster after a failed claim.

### OPS-06: Restore runbook and "setup recovery mode" are specified but do not exist (high)
- **Where:** `specs/persistence.md:85,93` and `docs/architecture/applications.md:86` ("run the Helm setup Job in recovery mode"). `internal/bootstrap/setup.go:55-58` has only the flags `--wait-schema`, `--config`, `--credential` and `--ca`. No value in `values.yaml` selects recovery. `docs/installation/*.md` contains no restore section. `docs/operations.md:110` lists PITR and complete-restore runbooks as todo.
- **Today:**
  - An operator with a corrupted volume has a pgBackRest repository on the same PVC set and no documented restore command.
  - There is no way to trigger the epoch-advancing recovery the spec requires, and no stated order for the four bundled stores (PG, SeaweedFS, OpenBao, Keycloak).
  - The spec also says to "scale the hub to zero" and then "run the Helm setup Job". That conflicts with setup being an ordinary hash-named Job that runs on `helm upgrade`, which in turn re-scales the hub.
- **Why friction:** Velero, CloudNativePG (`bootstrap.recovery`) and GitLab (`gitlab-backup restore`) each ship one restore command or value.
- **Trace:** The maintainer required tested backup/restore (REQ-DEP-004). The missing implementation and docs are a gap, not a decision.
- **Fix:** Add `recovery: {enabled: true, restorePoint: …}`. With it, the chart scales hub workloads to 0 and runs setup with `--recover`, which advances `fence_epoch`, reapplies exported audit and recomputes usage. Document one restore procedure per bundled store, plus a single "full restore" page.

### OPS-07: Bundled backups cannot leave the cluster, and backup health is only a readiness probe (high)
- **Where:**
  - `packaging/postgres/entrypoint.sh:26-34`: the repository is a local path, `repo1-retention-full=2` is fixed, and no S3/remote repository option exists.
  - `charts/asservat/templates/postgres-workload.yaml:108`: backup health is a readiness probe with a 26 h threshold. `publishNotReadyAddresses: true` (line 18) hides it from routing, so nothing alerts.
  - SeaweedFS, OpenBao and the Keycloak realm have no backup at all. The chart has no metrics endpoints, ServiceMonitor or PDBs (none found under `templates/`).
- **Today:** The operator gets same-disk backups, which the spec itself says "are not disaster recovery" (`deployment-profiles.md:45`). Off-site backup is not configurable. Stale backups show only as a NotReady container nobody watches. Evidence and key-store backups are left to the operator, undocumented. Without the OpenBao/key backup, evidence is unrecoverable.
- **Why friction:** CloudNativePG and the Bitnami/pgBackRest charts take an S3 repository and a schedule. GitLab and Sentry document a backup set for every stateful component.
- **Trace:** The maintainer accepted pgBackRest. Same-disk-only backup and silent staleness are agent-added gaps.
- **Fix:**
  - Add `services.postgres.bundled.backup.repository: {s3: …, existingSecret}`, plus schedule and retention values.
  - Expose a `/metrics` gauge for backup age and an optional ServiceMonitor.
  - Document backing up `<name>-openbao-state`/OpenBao data, `<name>-artifact-key`, `<name>-ids` and SeaweedFS volumes as one set.

### OPS-08: OpenBao is mandatory even though the spec requires local static-key alternatives for every purpose (high)
- **Where:** `values.schema.json` `services.keyService.provider` enum is only `external` or `openbao`. `charts/asservat/templates/key-service-workload.yaml:13` always wires `openBao`, `hub-api-deployment.yaml:4,98`, `docs/installation/helm.md:233-273`. Contrast `specs/deployment-profiles.md:31-33` (REQ-DEP-003: a local static-key alternative for every required purpose, and hub and connector certificates from the installation CA, "not from the key service").
- **Today:**
  - Every install runs OpenBao, bundled or external, alongside Asservat's own local key service (`<name>-artifact-key`). That makes two key systems.
  - External OpenBao requires hand-creating 2 transit mounts and 7 transit keys whose names embed the installation ID. That ID is only known after the first install (`<name>-ids`), so the first install necessarily fails.
  - It also requires 3 PKI mounts with 6 roles (the spec says certificates come from the installation CA), 1 KV mount, 2 Kubernetes auth mounts and about 19 policy/role pairs. The reference is Go source (`internal/adapters/providerconfig/setup_openbao.go`).
- **Why friction:** Comparable tools need one KMS key at most (Velero, Loki SSE, Sentry), or none. Vault-integrated charts such as cert-manager's vault issuer take one role and one path.
- **Trace:** The maintainer required local static-key services (ADR-063/064) and "no required SaaS". Mandatory OpenBao and its PKI mounts are agent-added and contradict ADR-330 D3.
- **Fix:** Add `services.keyService.provider: local` as the default. It covers transit-style signing and sealing with the existing local key service and generated keysets, and certificates come from the installation CA (cert-manager or Helm-generated). Keep OpenBao optional, for exactly one purpose: artifact key wrapping. With external OpenBao, setup creates its own mounts, keys and roles from one admin token Secret, as it already does for the bundled provider. Name keys after `installation.name`, not the generated ID.

### OPS-09: An external object store needs 9–13 separate S3 principals with hand-written prefix IAM (high)
- **Where:** `docs/installation/helm.md:216-231`, `charts/asservat/templates/secrets-job.yaml:46-56`, `docs/decisions/331-remote-cluster-join.md:88-91`, plus two more per joined cluster. The spec says "an operator-managed scoped credential Secret", singular (`specs/deployment-profiles.md:11`).
- **Today:** The operator creates `configuration-audit`, `owner-audit`, `federation-audit`, `publisher-audit`, `publisher-read`, `download-read`, `evidence-delete`, `operation-cleanup` and `operation-verify`. In combined mode they add `regional-write` and `regional-history`, and each joined cluster needs `regional-write-<c>` and `regional-history-<c>`. Each principal needs its own prefix policy, copied from `internal/adapters/providerconfig/seaweed_storage.go`, and its own Secret, some in the `<name>-downloads` namespace.
- **Why friction:** Loki, Tempo, Velero, Thanos, Sentry and GitLab take one bucket credential, optionally one per bucket. IRSA/Workload Identity users expect a single role.
- **Trace:** Agent-added. The maintainer wording is a single scoped credential. Wrap-only collectors are a maintainer invariant, but that concerns keys, not S3 principals.
- **Fix:** Default to one hub credential and one per region writer, two in total. Make per-purpose principals an opt-in `objectStore.external.principals` map. Also accept IRSA, Workload Identity or ambient credentials, meaning no Secret at all.

### OPS-10: AccessBindings that exist before the first acceptance wedge the permission subsystem unless an undocumented review ConfigMap exists (high)
- **Where:** `internal/application/configuration/reconciler.go:423-426` (returns `ErrDenied` when `len(snapshot.Bindings) > 0` and there is no review), `charts/asservat/values.yaml:283-285` (`hub.hub-worker.permission.review`: "Administrator-created initial review ConfigMap, needed only when bindings exist at the first acceptance"). The install docs never describe that ConfigMap.
- **Today:**
  - A GitOps repo that applies AccessBindings alongside the chart triggers this, and so does Argo CD syncing them first.
  - So does a reinstall after `helm uninstall`, because CRDs are kept and bindings live in application namespaces.
  - In each case the hub-worker's permission child refuses to start and nothing in the console explains why.
- **Why friction:** RBAC, Kyverno and Argo CD AppProjects take effect from whatever objects exist. Ordering-sensitive first acceptance is unheard of in comparable tools.
- **Trace:** Agent-added. "Trust the platform": an AccessBinding is already authorized by RBAC and the `bind` admission policy.
- **Fix:** Accept existing bindings on first start, as on every later relist, and drop the initial-review requirement and value.

### OPS-11: The schema accepts values that the runtime then rejects at startup (medium)
- **Where:** `values.schema.json` `hub.hub-api.public.previewSeconds` maximum 3600, against `internal/bootstrap/public_context_compose.go:195` (`PreviewSeconds > 300` is rejected). `standby` and `captures` have schema minimum 0 but runtime minimum 1 (same line). `downloadPlan.durationSeconds` has no schema maximum but a runtime maximum of 3600 (`public_downloads.go:55`).
- **Today:** `helm upgrade` succeeds, and then hub-api crash-loops with a generic composition error.
- **Why friction:** A closed values schema is meant to catch exactly this. Argo CD and cert-manager validate at render time.
- **Trace:** Agent-added drift.
- **Fix:** Make the schema bounds match the Go bounds and generate one from the other.

### OPS-12: Preview lifetime defaults to 120 s, and only about 10 sessions per user and 256 per installation are allowed (medium)
- **Where:** `charts/asservat/values.yaml:44-45,244`; `internal/adapters/postgres/browser.go:175-183` (installation `MaxSessions`; per-subject limit hard-coded to 10).
- **Today:**
  - A user who opens **Review collection** and reads the assessment for more than 2 minutes, for example to ask a colleague, gets an expired preview. The runtime caps it at 5 minutes.
  - An organization with more than 256 concurrent console sessions locks new logins out with `SessionCapacity`.
  - The trial profile sets 8.
- **Why friction:** Argo CD, Grafana and Sentry have no installation-wide session ceiling, and their form state does not expire within minutes.
- **Trace:** Agent-added bounds.
- **Fix:**
  - Default the preview lifetime to 15 minutes. Revalidate at submit, as the spec already does for authority.
  - Remove the installation session cap, or derive it from DB sizing with a default of 10,000.
  - Make the per-subject limit a value.

### OPS-13: Mandatory post-install "Initialize processing" console click before any capture (medium)
- **Where:** `docs/installation/small-profile.md:158-162`, `docs/decisions/210-installed-processing-changes.md:17` (ADR-127), `web/src/processing/ProcessingWorkspace.tsx:129-132`.
- **Today:** Even with every value configured, captures refuse with `processing/read/root-invalid` until a designated privacy operator signs in and clicks two buttons. The operator also has to name that identity at install (OPS-02).
- **Why friction:** Sentry, Pyroscope and Kubeshark start collecting once configured. Configuration in Helm values is itself the administrator's decision.
- **Trace:** Agent-added (ADR-127/210). It is not in the maintainer list. The maintainer did ask for "low-effort operator workflows".
- **Fix:** Have setup initialize processing from the values (`processors` plus retention purpose) under the installer identity, with an audit row. Keep the console route for later restrict and release changes.

### OPS-14: Generated credentials can never be rotated, and some value changes are silently ignored (medium)
- **Where:**
  - `charts/asservat/README.md:73` ("never rotated"), `charts/asservat/values.yaml:364-370`.
  - `docs/installation/helm.md:512-514` ("Never delete generated Secrets").
  - `internal/bootstrap/small_services.go:553-557`: serving TLS is kept if it exists, so later `hub.<component>.tls.dnsNames` edits are ignored.
  - `specs/deployment-profiles.md:45` requires tested credential/certificate rotation.
- **Today:** There is no supported way to rotate SQL passwords, S3 keys, the audit MAC, the artifact keyset or the Helm-generated CA. Adding a DNS name to a generated serving certificate has no effect and no warning.
- **Why friction:** cert-manager renews, Argo CD documents `argocd-secret` rotation, and the GitLab chart documents rotating each secret it generates.
- **Trace:** "Generate once, never on render" is a maintainer requirement (REQ-DEP-005). The lack of any rotation path and the silent ignoring of value edits are agent-added gaps.
- **Fix:**
  - Add `secrets.rotate: [sql-hub-api, …]`, a one-shot list: setup issues a new version, alters the SQL role, and pods pick it up through a checksum.
  - Use additive key versions for the artifact key and audit MAC, as the spec already defines.
  - Reissue the generated leaf when `dnsNames` change, keeping the CA.

### OPS-15: Bundled Keycloak cannot sit behind Ingress, and its hostname must resolve both from browsers and inside Pods (medium)
- **Where:** `charts/asservat/templates/keycloak-service.yaml:6` (ClusterIP or NodePort only), `docs/installation/helm.md:165-168`, `charts/asservat/values.yaml:453-455` (default NodePort 31451). `templates/keycloak-deployment.yaml:20-21` makes `maxConnections` "must be 5", a knob with one legal value.
- **Today:** The console has Ingress and HTTPRoute support, but the bundled IdP has neither. The operator must run NodePort (non-443 URLs) or hand-build an Ingress with TLS passthrough. They then have to make the external hostname resolvable from hub-api Pods (hairpin DNS). They also have to issue a second certificate.
- **Why friction:** The Argo CD (Dex) and GitLab charts route the IdP through the same Ingress, usually as a path or subdomain, and hub-api reaches it in-cluster.
- **Trace:** Agent-added.
- **Fix:**
  - Serve Keycloak under the console origin path `/auth` or a sibling host on the same Ingress or HTTPRoute, with `exposure.tls` reused.
  - Have hub-api use the in-cluster Service for back-channel calls (`KC_HOSTNAME_BACKCHANNEL_DYNAMIC`).
  - Remove the `maxConnections` value.

### OPS-16: Identity and fleet allow-lists are duplicated, with issuer and client repeated per entry (medium)
- **Where:** `charts/asservat/values.yaml:22-54,95-106`, `examples/helm/context-trial-site.example.yaml` (issuer typed three times).
- **Today:**
  - Eligibility (`identity.eligibleGroups/Subjects`), console clients (`identity.clients`) and fleet enrollment (`fleet.issuer/clients/groups/subjects`) are separate lists.
  - Each `processingOperators` entry repeats `clientID` and `issuer` for a single-issuer installation.
  - `fleet.issuer` duplicates `identity.issuer`.
  - The user must keep three lists consistent.
- **Why friction:** Argo CD and Grafana take one issuer and map groups to roles in one place.
- **Trace:** Agent-added. The maintainer chose one organization per installation.
- **Fix:** Default `fleet.*` to `identity.*`. Default each entry's `issuer` and `clientID` to the installation's. Let `processingOperators` and `fleet` admins be plain group IDs.

### OPS-17: Dead and duplicate values in the schema and examples mislead operators (medium)
- **Where:**
  - `values.schema.json` `installerFederation` accepts `endpoint`, `serverName`, `serviceType`, `nodePort`, `ownerAddress`, `ownerNodePort`, `ownerOperationAddress`, `ownerOperationNodePort`, `keyServiceEndpoint`, `keyServiceNodePort`, `evidenceStore` and `fleet`. No template reads any of them; only `federation.connector` is used (`_helpers.tpl:248`, `_hubapi.tpl:111`).
  - `examples/helm/context-trial-profile.yaml:110-125` and both site examples set them, for example `federation.serviceType: NodePort, nodePort: 31446`, which does nothing. Exposure really comes from `hub.federation.service`.
  - `hub.hub-api.peers` (`values.yaml:239-240`) and three separate `retentionTopologies` lists (`values.yaml:238,340,351`) are other cases.
  - So is the "former bootstrap.continuation…" wording (`values.yaml:128-140`).
- **Today:** Operators copy examples whose settings do nothing, or fill the same topology list three times.
- **Fix:** Delete the unread fields from the schema and examples. Collapse `retentionTopologies` into one top-level value. Describe values in operator terms, not their history.

### OPS-18: External PostgreSQL needs a stored CREATEROLE/superuser login, 5+ roles and about 117 connections (medium)
- **Where:** `docs/installation/helm.md:198-214`, `charts/asservat/templates/setup-job.yaml:15`, `specs/persistence.md:71`.
- **Today:**
  - The operator stores an admin `credentials.json` permanently. setup mounts it on every values change, because the Job hash covers values.
  - setup creates per-component runtime roles.
  - The server must be sized for at least 117 connections, or 122 with Keycloak.
- **Why friction:** Grafana, Argo CD, Keycloak and Sentry accept one pre-created database user and connect with a pool of about 10–20 connections. On RDS or Cloud SQL, CREATEROLE through a stored Secret is a security review item in itself.
- **Trace:** One login per process type is agent-added in REQ-DB-004. The maintainer chose PostgreSQL only.
- **Fix:** Offer `external.mode: singleUser`, where one owner login runs migrations and the runtime uses the same login. Keep per-role mode optional. Make the admin Secret needed only when the schema version changes, and lower the default pools.

### OPS-19: CRDs must be applied by hand before every install and upgrade (medium)
- **Where:** `charts/asservat/README.md:19-21,119-123`, `docs/installation/helm.md:124-126,277`.
- **Today:** A separate `kubectl apply --server-side -f charts/asservat/crds` is needed each time. Argo CD/Flux users must split the chart into two Applications.
- **Why friction:** cert-manager (`crds.enabled` with `keep`), Kyverno, Argo CD and Prometheus Operator ship CRDs as templates with `helm.sh/resource-policy: keep`, so `helm upgrade` upgrades them.
- **Trace:** Agent-added. Helm-native installation is a maintainer decision, which favours templated CRDs.
- **Fix:** Move the CRDs to `templates/` behind `crds.install: true` with the keep annotation, and keep `crds/` out.

### OPS-20: Download workers are a Pod-per-download Job, contradicting the architecture's long-running reader (medium)
- **Where:** `charts/asservat/values.yaml:352-362` ("Download workers (ADR-069) run as Jobs that hub-api dispatches"), `templates/download-worker.yaml`, against `docs/architecture/applications.md:65` (A-READ "Long-running unprivileged Deployment … scaled by replicas").
- **Today:**
  - Each native download schedules a Job Pod with a dedicated PriorityClass, a namespace and a separate S3 Secret.
  - The user waits for Pod scheduling and image pull per download.
  - Quotas, PriorityClass admission or a pull failure make downloads fail in ways the operator must debug.
- **Why friction:** Sentry, Grafana and Loki serve downloads from a running service.
- **Trace:** Agent-added; ADR-330 already specifies the Deployment.
- **Fix:** Implement A-READ as the specified Deployment, and remove the dispatch namespace, PriorityClass and per-Job Roles.

### OPS-21: Bundled users are managed in a second admin UI with a password read through kubectl (low)
- **Where:** `docs/installation/small-profile.md:144-156`, `specs/deployment-profiles.md:21` (REQ-DEP-002 asks for invite/recovery).
- **Today:** The operator decodes `bootstrap-admin-password` from a Secret, signs in to the Keycloak admin console and creates users and group memberships there. They must also be told not to edit `asservat_group_id` attributes.
- **Why friction:** Argo CD and Grafana print the initial admin in `NOTES.txt` and manage users in their own UI.
- **Trace:** Bundled Keycloak is a maintainer decision. The manual steps are an agent-added gap.
- **Fix:** Print the retrieval command in NOTES. Add an optional `services.identity.keycloak.initialUsers: [{username, groups}]`, with passwords generated into a Secret and required to be changed on first login. Make the attribute read-only through the user profile config the realm already defines.

### OPS-22: The trial keeps evidence for 5 minutes and caps it at 1 hour (low)
- **Where:** `examples/helm/context-trial-profile.yaml:105-109`, `docs/installation/small-profile.md:189-192`.
- **Today:** A first-time evaluator who captures, reads docs and comes back finds the evidence deleted.
- **Fix:** Default the trial to 24 h with a 24 h maximum. The 24 h figure is already the operations sample in `docs/operations.md:25`.

### OPS-23: Small paper cuts (low)
- **Namespace preparation:** The release namespace must be pre-labelled `restricted` by hand, and `--create-namespace` in `README.md:24` leaves it unlabelled. Fix: render the label through a namespace template, or drop the prerequisite, since pods already set restricted securityContexts.
- **TLS mode:** `exposure.ingress.enabled: true` still needs a manual `exposure.tls.mode: proxy` (`helm.md:96-104`). Fix: imply proxy when an Ingress or HTTPRoute is enabled.
- **Units:** Sizes are raw bytes (`download-worker.memoryBytes: 402653184`, `collector.ceilings`, every capacity field). Fix: accept Kubernetes quantities.
- **Rollback docs:** The docs say "an older image refuses a newer schema" (`helm.md:281-282`), but `setup.go:448` accepts any schema whose floor is at or below the image's version. State the real N/N−1 rollback window.
- **Setup wait:** Every install needs a separate `kubectl wait … job -l component=setup` (`helm.md:129`). Fix: make setup a post-install/post-upgrade hook, so that `helm --wait` (or Argo health) covers it, or document `helm upgrade --wait --wait-for-jobs`.
- **AccessBinding fields:** In the install walkthrough, an AccessBinding scoped to one Deployment requires its `uid` (`kubectl … jsonpath='{.metadata.uid}'`), and `reason` is a required field (`crds/accessbindings.yaml`, `small-profile.md:170-182`). RoleBindings need neither. Fix: name-only workload selection with server-side UID capture, and an optional `reason`.

---

## Counts

- High: 10 (OPS-01 to OPS-10)
- Medium: 10 (OPS-11 to OPS-20)
- Low: 3 entries (OPS-21 to OPS-23; OPS-23 bundles six paper cuts)

Trace:
- **Agent-added:** most findings.
- **Agent-added detail on a maintainer decision:** OPS-01/02/15/21 (bundled Keycloak), OPS-03 (storm/storage protection), OPS-07 (pgBackRest), OPS-14 (generate once).
- **Unimplemented maintainer requirement:** OPS-06 (restore) and OPS-08 (local static keys), both specified but not delivered.
