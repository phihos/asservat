# Helm-native runtime input field map

Working contract for the Helm-native installation
([plan](helm-native-install-plan.md)). Classes:

- **H**: Helm value or chart constant, rendered into the component ConfigMap.
- **N**: read by name from the Kubernetes API at startup (only where SQL keys
  on the value).
- **S**: generated once by the `secrets` Job into a named Secret.
- **J**: produced by `setup` or read from SQL/OpenBao at startup.
- **D**: drop.

S values are not known at render time (hooks run after rendering on first
install), so every loader merges: the Helm config file, the IDs Secret
(`<release>-ids`, mounted at `/run/asservat/ids/<key>`) and credential files.

## Remaining slice-0 items on the hub-api installed path

`owner_observation_deployment.go:270` builds a pinned workload guard, `:294`
runs `VerifyStartup(manifest, mounted)`, `:305` `VerifyPublicProjection`;
`owner_inputs.go:149,154,186` require the guard, activation and projection
UID. These go first.

## Shared fields (all components)

| Field | Class | Replacement |
|---|---|---|
| InstallationID, ClusterID, PermissionRootID, IssuerEpoch/RecoveryEpoch, BrowserRootID, PeerID | S | `<release>-ids` Secret; `setup` seeds trust/root rows with the same values |
| Namespace.Name | H | `.Release.Namespace` / downward API |
| Namespace.UID | N | one namespace GET; SQL rows are keyed by `namespace_uid` |
| Kubernetes{Endpoint,Roots} | H | in-cluster service host and SA `ca.crt`; delete the field |
| Postgres, AuditStore, OpenBao endpoints and roots | H | values, bundled defaults |
| Mount/key/role names | H | chart constants shared with `setup` |
| Every `*Guard`, ConfigurationProbes, SchedulingLeases, InitialHistoryProbe, CapacityProbe, probe accounts/audiences | D | — |
| WorkerObjectReference.UID of SAs, Deployments, Secrets, Leases | D | match by name |
| WorkerObjectReference.UID of source ConfigMaps | N | take `metadata.uid` from the plain read |
| ProviderAuthentication accessor/recipe/UIDs, ProviderRecipeSHA256 | D | drop runtime OpenBao recipe verification (`providerconfig/*_provider_verify.go`); `AuthMount` stays H |
| Activation, ProviderInputs, RoleRootUID, RoleSetupID, OperationID, claims, receipts, LayoutDigest | D | — |

## hub-api (`/run/asservat/hub`)

| Field | Class | Replacement |
|---|---|---|
| Format, Connections, Concurrency, KeyService, AuditStore, Postgres | H | |
| ConfigurationUID | N | owner-configuration ConfigMap UID |
| APIContextStarts account names, CapacityAudience | H | account UIDs D |
| Observation.Activation, Template/Image/ProtectionDigest | D | peers trust the owner PKI leaf |
| Observation.Peers[] | H | per remote region; combined mode: IssuerEpoch/PeerID S |
| LocalCapacity.Keys, WorkloadGuard.{Label,Annotation}Keys, Caller.Account | H | guard, probe fields D; admit hub-worker by TokenReview username |
| Native.ConnectorRoots | J | OpenBao connector PKI CA |
| Native.WorkerAPIs[].{ClusterID,Namespace.Name,Kubernetes} | H | Namespace.UID N |
| Native.RetentionTopologies[].{TargetClusterID,Name} | H | UID, SHA256 D |
| Public numeric settings, Origin, BrowserAudience, ProviderRoots, Port, Version, CaptureHistory, OperationAudit, DownloadPlan, PermissionDelegations | H | today hard-coded in `owner_promotion.go:85-97` |
| Browser/IdentitySettings.Name | H | UID N |
| SessionTransit, WorkerPKI.{Mount,Role}, WorkSigning.{Mount,Name} | H | |
| WorkSigning.{Version,KeyID,PublicKey}, WorkerPKI.Roots | J | read transit key / `pki/ca/pem` at startup; IssuerEpoch S |
| ClusterCatalog, WorkerConfiguration, DownloadEnvironment, Processing, Fleet.Settings source names | H | guards D |
| DownloadEnvironment paths, Fleet.{ChannelMount,DeliveryProfile} | H | |
| CaptureAuditPolicy, Capacity{QualificationID,Digest,AccountVersion}, AuditStoreID | J | read current SQL qualification by PermissionRootID |
| ArtifactKeyID | H | derived constant |
| RuntimeProjection | D | |

Files: `owner-pod.token`, `provider-auth.token` (projected tokens, H);
`sql-*.json`, `audit-storage.json` (S); `oidc-client-secret`, `public-tls.*`
(H, existingSecret/cert-manager); `kube-probe.token`, `*-roles.json`,
`browser-*.token`, `work-sign.token`, `worker-issue.token` (D);
`worker-controls.json` to be traced.

## hub-worker (`/run/asservat/hub-worker`)

| Field | Class | Replacement |
|---|---|---|
| FleetSource/OwnerSource names | H | UIDs N |
| FleetGuard, OwnerGuard, Activation, ProviderInputs, ProviderAuthentication accessor/recipe/accounts | D | |
| LeaderLease.Name | H | UID D; leader election may create the Lease |
| ProviderAuthentication transit names | H | |
| Capacity: Control, Clusters[].Keys, Processing.Source.Name, Paths | H | guards, probes, role-root D; AccountVersion, Qualification J |
| Permission: StatusUsers, Delegations, Retention, WorkerConfiguration names, AuditTransit, Browser, Identity | H | guards, probes, UIDs D |
| ContextDeletion.Signing keys | J | read transit |

Files: `sql-*.json`, `provider-audit-storage.json` (S); subdirectory configs
H with S credentials; role manifests, `kube-probe.token` D. The cleanup,
capacity and permission children start when their subdirectory is mounted,
not on journal receipts.

## federation, key-service, publisher

- federation: Port, Concurrency, KeyService, AuditStore, Postgres H; Owner
  guard inputs D except Namespace.Name; ConfigurationUID and Namespace.UID N;
  Connector.Backing J (SQL `connector_identity_root`); `sql-federation-*.json`,
  `federation-audit-keys.json`, `audit-storage.json` S; TLS H.
- key-service: Port, Concurrency, KeyID, KeySource.Name H (UID N);
  RecoveryEpoch S; KeyClientRoots, ConnectorClientRoots J; WorkerProfile copy
  D (read the ConfigMap); catalog guard and topology pins D; `sql-key-*.json`,
  artifact root key S; TLS H/J.
- publisher: poll/batch/stores/verifier H; Evidence.StoreID, IssuerRoots J;
  Owner, OwnerWorkload.UID, guard (`publisher.go:298`), ProviderAuthentication
  except AuthMount D; `sql-public-*.json`, `evidence-read.json`,
  `audit-storage.json` S.

## connector, download-worker, collector

- connector: names, Hub endpoint, collector, settings, stores, owners
  address, concurrency, Alertmanager, identity mappings, profile endpoints H;
  IssuerEpoch, PeerID, PermissionRootID S in combined mode, H from the
  enrollment offer for remote regions; Namespace.UID, Source.UID N;
  Deployment.UID N only if lifecycle reads need it; all guards, probes,
  credential/start UIDs, capacity owner digests D; IssuerRoots J.
- download-worker: per-dispatch flags and control file stay; worker
  configuration names H; UIDs and ControlConfig.SHA256 D; RecoveryEpoch S.
- collector: already clean; projected node token and downward-API env.

## SQL logins

Role names are derived (`as_<inst-hex>_pub_NN`, `_cfg_0N`, `_own_06`).
`secrets` writes one Secret per component with `sql-<purpose>.json` keys in
the existing `OwnerSQLCredential` format; `setup` creates missing roles,
alters passwords and applies grants from the compiled plan, never drops and
recreates (SQL keeps OIDs). Runtime keeps only `session_user = derived name`;
manifests, role comments and layout digests go. Reducing to one login per
process (evidence check group 2) is a later slice.

## Persisted digest and OID couplings

1. `protection_digest` columns (`retention_source`, `processing_root`,
   `connector_identity_profile`, `cluster_bootstrap_activation`): replace the
   pin-based digest with sha256("asservat-configmap-source/v2", clusterID,
   namespace name, ConfigMap name), no migration until slice 4.
2. Owner workload protection digest (owner enrollment, owner configuration,
   observation replies): same deterministic digest of (cluster, namespace,
   Deployment name), later removed from replies.
3. Capacity qualification guard/template/image digests: deterministic
   namespace digest; template and image digests D.
4. Role OIDs in SQL resolve via `session_user`; keep roles stable.
5. `namespace_uid`/`source_uid` keys are N values, stable across upgrades.

## Startup order

`secrets` (pre-install) → bundled PostgreSQL/OpenBao/SeaweedFS → `setup`
(post-install). SQL-using Deployments wait in an init container for the
compiled schema version. Components retry peers at runtime instead of
blocking on each other.

## Decisions (2026-11-13)

1. Kubernetes UIDs used as SQL keys (fleet and owner configuration
   ConfigMaps, namespaces) are read by name at startup by the runtime and by
   `setup` (read-only GETs). No pin comparison; values are stable across
   `helm upgrade`. No migration.
2. Generated IDs: every loader merges the `<release>-ids` Secret with its
   rendered config file. No `lookup`.
3. SQL role creation: bundled PostgreSQL uses the bundled admin; an external
   database needs an administrator credential for `setup`. Role names are
   derived; roles are created if missing, never dropped.
4. A new forward-only migration relaxes `capacity_setup_original_valid` and
   `capacity_audit_reader_pin_valid` (00054) to role name, attribute and OID
   checks; `fleet_initial_activation` is no longer required.
5. `setup` is an ordinary Job whose name carries a hash of chart version,
   image and values (GitLab migrations pattern), not a Helm hook. SQL-using
   Deployments wait in an init container until the schema is current.
6. Capacity initialization moves into hub-worker, after its first permission
   acceptance; `setup` does not depend on a running hub-worker.
7. OpenBao self-init keeps only the setup auth mount, policy, role and
   marker; `setup` ensures mounts, policies, auth roles, PKI roles (upsert)
   and transit keys (create if missing).
8. `secrets` extends today's small-services-prepare hook: create-once
   Secrets, `existingSecret` overrides, no workload/PVC reads.
9. No first-installation audit record, witness or activation receipt.
