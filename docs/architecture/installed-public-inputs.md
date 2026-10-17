# Installed public inputs: producer map

This is the producer inventory for the promoted installed hub-api
([ADR-182](../decisions/182-installed-owner-promotion.md),
[ADR-184](../decisions/184-promoted-owner-first-launch.md),
[ADR-185](../decisions/185-public-sources-and-cluster-catalog.md)). It
records, for each `OwnerDeployment.Native` and `.Public` input:
- which product code produces it;
- where tests set it up today;
- the order the continuation must follow.

It describes the 2026-10-15 state. "Test-only" means the setup exists only
in `test/integration` helpers. Those helpers never confer production
authority.

## Inputs

| Input | Product producer | Test-only setup | Depends on |
| --- | --- | --- | --- |
| Browser and identity settings | ADR-185 continuation step (implemented with the catalog) | `kubernetes/browser_settings_test.go`, `identity_policy_test.go` | chart values |
| Cluster catalog and guard | ADR-185 continuation step | — | workload-guard probe slots (ADR-185) |
| Capture, normal and resolution audit policies; `AuditStoreID` | Partial: hub-worker `RootBackingCoordinator` reserves and backs the pools. `InitializeCapacity` and `NewCapacityAuditProfiles` have no product caller. | `capacity_native_inputs_test.go`, `capacity_sql_matrix_test.go`, `context_native_content_test.go` | capacity initialization, then hub-worker reserve, back and publish (`ReadyAt`), then `read_capacity_audit_profiles` |
| `OperationAudit` | None (limits only) | `context_native_content_test.go` | retention must be no longer than both lanes' `retained_seconds` |
| `ArtifactKeyID` | None. The key service writes `local_key_configuration` from `KeyServiceDeployment`, which has no producer. | `download_keys_helpers_test.go`, `local_key_lifecycle_test.go` | key-service deployment |
| `SessionTransit`, `WorkSigning`, `WorkerPKI` | None. The public provider recipe exists; no key or PKI role creation. | `browser_sessions_test.go`, `policy_submission_test.go`, `worker_pki_test.go` | provider artifact phase and applier key admission (ADR-184) |
| `WorkerConfiguration` | None. Admission and observer exist without product callers; no product role inserts the SQL revision. | `download_jobs_kube_test.go`, `worker_configuration_kube_test.go`, `download_dispatch_helpers_test.go` | worker namespace (must be the hub control namespace), account, PriorityClass, immutable control ConfigMap, store Secret, SQL acceptance |
| `DownloadEnvironment`, `DownloadPlan` | None | unit only (`download_environment_test.go`) | worker configuration revision, owner pool revision |
| `Native.WorkerAPIs` | None | unit only | hub cluster and worker namespace |
| `Native.RetentionTopologies` | None. `retention-topology.md` leaves pin provisioning to the installer. | `retention_topology_test.go` | — |
| `Native.ConnectorRoots` | None | `federation_regional_native_test.go` | connector PKI |

## Capacity readiness chain

`PublicRuntimeSQLRoles.InitializeCapacity` cannot run inside the current
public-roles phase. Its prerequisites, in dependency order:

1. **Storage CRDs and objects.** The chart ships no `EvidenceStoragePool`
   or `EvidenceBudgetPolicy` CRD. The qualification references real pool
   UIDs and the processing source UID.
2. **Guards.** The capacity admission policy
   (`asservat-<id>-capacity-guard`), each cluster's capacity namespace
   guard, and the processing source ConfigMap with its guard. Only tests
   create them today. The owner workload guard's `CapacityProbe` branch and
   the worker's capacity RBAC already exist.
3. **`CapacityGuard`.** Built from the bridge's observer and worker probe
   clients. Its digest becomes `SourceGuardDigest`, which
   `accept_capacity_source` compares with the hub-worker guard.
4. **Qualification.** `app.CapacityQualification` with its
   `RootBackingInput` has no product producer.
5. **Permission root.** The setup permanently records `PermissionRootID`,
   which the owner selection mints after the public roles. The
   `permission_stream` row must be fresh, with acknowledged initial and
   epoch audits. [ADR-189](../decisions/189-installed-permission-stream.md)
   produces it: the continuation applies the permission guard and
   publishes the permission projection after the selection, and the
   hub-worker's permission child runs the reconciler and the authority
   publisher.
6. **The call.** `InitializeCapacity` needs the public role root and
   producer, which the public-roles phase closes today, kept open past the
   selection.
7. **Hub-worker readiness.** The installed hub-worker starts its
   `RootBackingCoordinator` only after the `CapacityRuntimeProjection`
   Secret holds a complete `CapacityDeployment` (local owner, control pin,
   cluster guards, processing source, qualification). It sets `ReadyAt`;
   only then are the audit profiles readable.

## Order inside the continuation

Corrected after ADR-189/190/192 (2026-10-15):

1. Worker phase (ADR-183), unchanged.
2. Public sources (ADR-185): settings and the empty catalog with its guard.
3. Owner selection, then the permission stream (ADR-189).
4. Capacity initialization (ADR-190 steps 1–4): sources, guard proofs,
   qualification and `InitializeCapacity`.
   - Identities and the setup time derive from the public role setup, so a
     replay matches the committed claim ([ADR-192](../decisions/192-capacity-before-download-paths.md)).
   - The owner's local capacity observation input is set here.
5. Owner outbox, inbox, projection and launch (ADR-184). Until promotion
   the launched owner is observation-only and serves the local capacity
   observation itself.
6. The capacity projection, with an empty download path set (ADR-192); the
   hub-worker then runs capacity to `ReadyAt`.
7. Pending:
   - **Regional provisioning.** The connector installation brings the first
     download path. That needs a dedicated worker namespace, the worker
     configuration source and guard, hub-worker acceptance through
     `WorkerConfigurationObserver`, the evidence store and key service
     inputs, and the enrollment and native exchange endpoints.
   - **Retention topology and connector roots.**
   - **Promotion.** Native and Public are derived, then the promoted owner
     launches (ADR-184).

The capacity `-processing-source` and the hub-api's `-download-environment`
carry the same contract. When a path is added, both carry the same settings.
