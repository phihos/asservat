# Install Asservat with Helm

Helm is the official installation and upgrade path. The [chart README](../../charts/asservat/README.md) contains the runnable commands and complete values table for the current package. The [operations contract](../operations.md) describes the eventual runtime profiles. TASK-11, REQ-UX-001 and REQ-ARC-001 cover installation ergonomics and role isolation.

For a source-built installation through enrollment, pod-status capture and native download, follow the [external-services context trial](context-trial.md). Its reference runs cover separate hub/workload APIs and a shared API with preloaded images; the shared path uses hub Helm followed by the regional CLI.

For a trial without separately operated PostgreSQL, S3, key-provider or identity services, use the [bundled-services context trial](small-profile.md). Its site values, source image builds and remaining qualification limits are explicit.

## Current scope

Version `0.1.0-dev.1` packages eight structural CRDs: AccessBinding,
PermissionSource, DebugPolicy, EvidenceRetentionPolicy, EvidenceBudgetPolicy,
EvidenceStoragePool, CapacityReservation and CaptureProfile, plus a nonauthorizing release
inventory. All three topology modes are accepted. By default, no runtime Deployment, collector, public route, database migration, default permission grant or baseline policy is installed. The optional ADR-137 bootstrap hook packages initial schema and activation. Explicit runtime continuation adds its final command to the same fixed runner Pod. The consolidated runner passed the context trial in the owned two-cluster reference environment; the shared-API hub-Helm/regional-CLI path also passes, while registry distribution remains outside those results. Default policies must be protected and accepted by the runtime before becoming authoritative; rendering a policy does not establish acceptance.

The initial external identity provider is **Keycloak**, selected by the maintainer. Reuse the [qualified reference profile](../architecture/keycloak-profile.md) for its browser/MCP implementation; issuer/client/group configuration remains independently protected. The maintainer subsequently required an internal users/login option and small-deployment alternatives under [ADR-063](../decisions/063-small-deployment-alternatives.md). The small profile adds independently selectable bundled Keycloak, PostgreSQL, OpenBao and SeaweedFS. Its all four bundled services context workflow has fresh installed qualification; physical restore, mixed-provider installed matrices and broader lifecycle qualification remain pending. Its explicit bundled-Keycloak selection prepares a retained realm/client/group configuration with no default human password. External identity selection never installs a realm. Never put an administrator password in Helm values or infer authority from group display names. The context trial includes actual Keycloak browser/MCP sign-in and installer acceptance; broader identity/deployment profiles remain unfinished.

The chart's `runtime.enabled: false` constraint is temporary and explicit. Add runtime role templates, typed values, Secret-reference validation, network/RBAC tests and end-to-end installation qualification in the same implementation slice as each usable role. Do not change this switch to true merely because a chart renders. No placeholder image, prototype console or no-op server should masquerade as the application.

## Optional initial bootstrap checkpoint

This development package offers `bootstrap.enabled: true` for the existing
external PostgreSQL, S3 and OpenBao path. The actual four-command chart and
private-registry composition has [native evidence](../architecture/helm-bootstrap.md#qualification-and-remaining-installed-prerequisites).
Keep `runtime.enabled: false`; runtime continuation is a separate explicit
option below. Successful bootstrap alone does not provide an installed
browser/MCP investigation service; see the exact
[remaining installed prerequisites](../architecture/helm-bootstrap.md#qualification-and-remaining-installed-prerequisites).

Use a verified chart archive and its actual product image digest. Select a
trusted dedicated bootstrap namespace with Pod Security `restricted`, distinct
from the product target namespace. This explicit administrative entry is not a
claim that a previously used namespace is clean. The chart creates the trusted
installer account/RBAC; the product derives every dynamic UID/OID and protects
its own state. Operators do not compute digests or edit journals.

Supply these existing Secrets in that bootstrap namespace. Keep private files
outside values, shell arguments and release data; provision them through the
organization's normal secret workflow. The public JSON schemas define their
closed bodies.

| Reference | Exact private keys | Upstream authority supplied |
| --- | --- | --- |
| `bootstrap.secrets.producer` | `postgres-administrator.json`, `provider-material.json` | Trusted SQL setup administrator; finite installation-only OpenBao issuer; explicit audit-store credentials and their finite use bound |
| `bootstrap.secrets.schema` | `postgres-ddl.json` | Separate DDL connection identity; no provider or generated manager credential |
| `bootstrap.secrets.retirement` | `postgres-administrator.json` | Trusted SQL administrator to positively retire the exact original generated manager and its sessions |
| Optional `bootstrap.registrySecret` | `.dockerconfigjson` in a `kubernetes.io/dockerconfigjson` Secret | Explicit credentials for the pinned image registry only |

SQL files contain the closed `username` and `password` object consumed by
[the existing private SQL credential decoder](../../internal/contracts/owner_deployment.go).
Provider material follows [its private schema](../../specs/contracts/initial-bootstrap-material.schema.json),
including the supplied `storageUseUntil`; that timestamp does not create or
extend upstream credentials. No password/root token belongs in Helm values.
The external database must be empty for a fresh initial installation. Existing
state is resumed only through the original protected installation; this is not
a restore or migration adoption tool.

Generate the exact nonsecret OpenBao prerequisites using the matching local
product binary:

```sh
asservat installer-provider-recipe > provider-prerequisites.json
```

This prints the transit mount/key/type, exact three ACL policy bodies, two
bounded token-role bodies and finite issuer-token request. It makes no provider
request and loads no credential. The provider administrator reviews/applies
those prerequisites with their existing tooling and places only the returned
limited issuer credential into the private producer input. Do not overwrite an
existing key or substitute provider-root credentials. Flags match the chart's
`bootstrap.providers` and `bootstrap.keyService.auditMount/auditKey` values.

Regional executors also require a separate metadata-only storage capability in
`history-storage.json`, alongside the evidence writer's `evidence-storage.json`
in the existing protected regional credential Secret. Supply it to
`installer-cluster` using `--history-credential`. The regional Helm projection
requires both entries. Use the same configured evidence bucket and store ID;
the history capability only operates below
`history/v1/<permission-root>/<regional-cluster>/`. It has no evidence read or
delete rights and no key-unwrapping permission.

Render the exact proposed history permissions from the existing public offer
and protected bootstrap record:

```sh
asservat installer-provider-recipe --history-offer regional-offer.json --history-bootstrap bootstrap.json > provider-prerequisites.json
```

This additional output contains `regionalHistory.seaweedIdentityActions` and
`regionalHistory.s3BucketPolicy` separately. The first is Seaweed's identity
configuration; the second is the bucket-policy proposal with prefix-conditioned
inventory and explicit evidence denials. Review and merge it with the bucket's
existing policy, preserving evidence-writer protections. An external provider
administrator provisions the identity and supplies its closed `accessKeyID`,
`secretAccessKey` and `sessionToken` credential input. This command emits no credential, makes no provider
request, and does not issue an S3 identity. Automatic bundled S3 provisioning is
not qualified by this output. Other S3 providers require their own qualification
of prefix-conditioned inventory, version deletion and multipart cleanup.

The focused `make history-storage-integration` gate checks the production policy
constructor against the pinned Seaweed backend: history write/read, retained
versions and multipart cleanup succeed; evidence and foreign-prefix read,
delete and inventory fail. This is storage-capability evidence, distinct from
installed SQL authorization, encrypted parameter production and history repeat.

Keep nonsecret choices in one values file. Copy the `bootstrap` section of
`charts/asservat/values.yaml`; set `enabled: true`, a stable `name`, distinct
`targetNamespace`, the original verified `image: repository@sha256:…`, the three
Secret references, PostgreSQL endpoint/database/CA PEM, audit-store
endpoint/region/bucket/CA PEM, OpenBao endpoint/CA PEM, and explicit fleet
issuer/client/stable subject or group IDs and finite ceilings. The supplied
services and bucket remain administrator-owned. PEM is normalized by the
product; generated pins never become an operator chore. The API CA defaults to
the native public projection. An empty `probeAudience` uses the first audience
of the projected API token, which is the API server's primary one (k3s and
RKE2 tokens also carry their distribution name); set it to choose another.

After the references and public values exist, the fresh operation is one Helm
invocation (apply/upgrade the CRDs separately as documented):

Public continuation with capacity also prepares operation-audit cleanup in the
existing hub worker (ADR-323). Its phase-3 provider recipe includes
`operationCleanupStorage`: provision the two distinct storage principals for
that exact audit bucket and permission-root prefix, preserving existing writer
denials. Supply their credential JSON files to `installer-provider-apply` with
`--cleanup-audit-credential` and `--cleanup-verify-credential`. The cleaner needs
version/multipart inventory and deletion plus conditional creation of retirement
certificates; the independent verifier cannot write or delete. Neither gets
evidence-bucket or storage-administration rights. The recipe does not provision
S3 IAM. Provider authentication uses the worker's existing native identity and
bounded renewable provider lifetimes; no static provider token is supplied in
these files. Current candidate installed qualification is recorded in
`docs/implementation-progress.md`.

Public continuation optionally accepts `bootstrap.continuation.public.captureHistory`
with both `perSelector` (1–1,000) and `perInstallation` (1–100,000). Omission uses
1,000 and 100,000 respectively. These are retained history-entry ceilings, in
addition to existing storage capacity; encrypted settings reserve four object
slots and up to 1,671,168 bytes each. Lower limits evict the oldest eligible
history from its originating allocation. Physical charges remain until cleanup
confirms deletion. History exhaustion reports unavailable settings while the
accepted capture continues. These settings do not change evidence retention.

```sh
helm upgrade --install asservat ./asservat-0.1.0-dev.1.tgz \
  --kube-context MANAGEMENT_CONTEXT --namespace asservat-bootstrap \
  --skip-crds --values bootstrap-values.yaml --wait --timeout 15m
```

The fixed hook runs produce, schema, preparation and retirement in order with
one original image, Restricted security and memory-only private scratch. With
continuation enabled, it runs `installer-continue` as the final container,
without another producer or scratch volume. Bootstrap alone creates no runtime
services. The entire Pod retains its 1,800-second ceiling; original
effect/credential/cleanup deadlines still apply independently of Helm's wait
timeout. Retain this original bootstrap image
and desired input on later chart-only replay; changing an image/bundle is not an
application upgrade protocol.

On success the hook is deleted. Product seed/history/tombstones and protected
original identities remain outside Helm ownership. V3 positively removes its
managed SQL/provider input copies and sanitizes the seed only after qualified
closure. It does not delete operator-owned input Secrets, revoke their upstream
credentials or erase etcd/backups/caches. Once initial closure is verified,
operator setup inputs may be removed; repeated completed hooks start with those
files unavailable and take the protected passive path. The original registry
pull Secret remains necessary if a future node must obtain the image.

For a private registry, use a closed Docker config with exactly the pinned
registry and Basic username/password or equivalent `auth`, at most 4 KiB.
Credential helpers, external commands, identity tokens, headers, unrelated
registries and conflicting fields are unsupported. Validation names the remedy
without echoing credentials. The producer copies the normalized key into the
already journaled activation provider Secret; the activation process mounts only
its original seven files, while kubelet handles the pull key. Its positive
cleanup covers that managed copy too.

### Interrupted or failed hook

A timeout is an unknown orchestration result. Observe the fixed
`<bootstrap.name>-bootstrap` Pod; do not delete a live/unknown Pod or retained
product state, force an upgrade, enable before-hook deletion, or use rollback as
recovery. A failed hook intentionally blocks blind replacement. After a positive
terminal result, use the matching product CLI:

```sh
asservat installer-resume --context MANAGEMENT_CONTEXT \
  --namespace asservat-bootstrap --name asservat
```

Normal `--kubeconfig`/`KUBECONFIG`/current-context resolution applies; the command
reports its resolved scope and never falls back to in-cluster credentials. It
validates the exact original bootstrap/runner input and fixed Pod, including
the final continuation's termination when enabled, then removes only its
terminal UID/resource version. It does not read setup credentials or finish an
installation. It does not need the downstream continuation ConfigMap to remove
an already terminated runner. Retry the same Helm command explicitly afterward. Expired original
effects or contradictory product state require qualified recovery, not new IDs.

Correcting malformed public input creates a new immutable revision snapshot;
a retained hook still points at its original one. Old nonsecret snapshots are
currently kept until positive unreferenced cleanup is qualified. Never remove a
snapshot referenced by a running, retained or unknown hook. This retention is
chart housekeeping, not ownership of product history.

### Runtime continuation (development)

[ADR-183](../decisions/183-installer-runtime-continuation.md) defines the
continuation enabled with `bootstrap.continuation.enabled: true`. It starts
the configuration worker and the owner after first activation. It now runs as
the final container of `<bootstrap.name>-bootstrap`, after retirement has
refreshed the shared public/history projection and removed its maintenance
credential. The separate continuation Pod and duplicate projection producer are
removed. Installed evidence for the earlier composition does not qualify this
new layout; see [implementation status](../implementation-status.md). Keep
`runtime.enabled: false`.

When upgrading from the separate-Pod layout, Helm checks the legacy
`<bootstrap.name>-continuation` Pod through the selected administrative
connection. A nonterminal, node-lost or deleting legacy Pod blocks rendering.
Resolve that original operation before retrying; the chart never deletes or
adopts it. Completed legacy Pods may remain. Offline `helm template` cannot
perform this live overlap check.

Before enabling it, prepare these in OpenBao and the audit store:

- two Kubernetes auth mounts, one for the worker and one for the owner, each
  with its reviewer configuration;
- the owner PKI mount (`ownerPKIMount`) and its CA.

Set the two mounts' paths and accessors and the owner PKI roots PEM in
`bootstrap.continuation`. Keep `postgres-administrator.json` in the producer
Secret until the continuation completes.

The continuation runs as the runner account and uses its own rotating API token.
Its existing provider waits remain inside their original runtime journal
window and the same Pod's 30-minute ceiling; joining the phases grants no new
time or retry. At each wait it publishes an exact public
recipe to the outbox ConfigMap `asservat-<installation>-installer-outbox` in
the bootstrap namespace. For each wait, run the applier with your own OpenBao
administration (`BAO_ADDR`, `BAO_CACERT`, `BAO_TOKEN`) and a scoped audit
storage credential:

```sh
asservat installer-provider-apply --context MANAGEMENT_CONTEXT \
  --namespace asservat-bootstrap --installation INSTALLATION_ID \
  --audit-credential worker-audit.json
```

The two waits need different storage credentials:

| Wait | Credential scope |
| --- | --- |
| Worker | Read and write under the worker configuration prefix stated in the recipe |
| Owner | Read and write under the owner enrollment and certificate prefixes stated in the recipe |

Create each principal with your storage backend's IAM. The recipe states the
exact prefix, the allowed operations and the denials (no delete, no
versioning or policy change). Versioning must be enabled.

The applier only creates the recipe's ACL policies, auth roles and PKI roles.
It never overwrites an existing object, and refuses any other path. It then
writes a ten-minute read-only inspection token and your credential to the
inbox Secret. The continuation verifies the provider through that token
before it publishes or launches anything, then deletes the inbox.

## Delegate permission management

Set `bootstrap.continuation.public.permissionDelegations` before the initial
runtime continuation to let selected Kubernetes identities author AccessBindings
within a fixed envelope. The same entry names browser identities allowed to
preview those changes. The default `[]` delegates nothing. This packages the
existing [permission guard](../architecture/permission-acceptance.md) and
[access preview](../decisions/237-permission-impact-preview.md) configuration;
it adds no runtime component or automatic grant.

For example, inside the rest of your bootstrap values:

```yaml
bootstrap:
  continuation:
    public:
      # Also configure origin, issuer, clients and eligibility as above.
      permissionDelegations:
        - writers:
            - kind: Group
              name: payments-admins
          clusterID: 10000000-0000-4000-8000-000000000001
          namespace:
            name: payments
            uid: replace-with-the-existing-namespace-uid
          workloads: []
          roles: [evidence-reader, workload-maintainer]
          issuers: [https://identity.example/realms/company]
          previewers:
            - issuer: https://identity.example/realms/company
              kind: Group
              id: payments-leads-stable-group-id
```

Use the installation's actual enrolled cluster ID and current target namespace
UID. An empty `workloads` list covers that namespace; otherwise name each exact
`Deployment` or `StatefulSet` with `kind`, `name` and `uid`. Namespace or workload
recreation requires a new qualified envelope. `roles` may contain only
`workload-maintainer`, `evidence-reader`, `evidence-owner` and `action-approver`;
`issuers` limits which subject issuers the writer may bind. At most 64 envelopes
are accepted. Every envelope requires at least one writer and one previewer.

`writers` uses the Kubernetes API server's authenticated username or group
(`kind: User` or `Group`); a service account is represented by its exact `User`
name, `system:serviceaccount:NAMESPACE:NAME`. `previewers` uses the browser
issuer's stable subject or group ID, independently of Kubernetes identity
mapping. A previewer gains no Kubernetes write permission. Writers still need
ordinary Kubernetes RBAC to write AccessBindings in the hub control namespace;
the admission guard additionally enforces the envelope's scope, roles and
issuers. This does not delegate PermissionSource trust administration or
retention administration.

These are public, immutable installation inputs. Nonempty delegations require
`public.origin`, and enter the continuation and original runner digests. Empty
lists are omitted from the wire to preserve existing installation identities.
A completed installation cannot change its guard through a chart-only replay:
changing these values creates a different input and requires a separately
qualified guard revision. This chart change does not implement that migration.
Do not delete the protected guard or installation records to force a changed
envelope.

Packaging complexity assessment: the observed omission blocks every Helm user
who needs delegation; the capability is already implemented and required by
REQ-PER-002. This change adds **0** API calls, watches, credentials, runtime
components, background tasks, fallback states or default grants. It passes
nonsecret values through the existing protected installer path, with the same
finite bounds. Leaving the field unavailable would require hand-editing the
installer input outside the official Helm path. No new runtime mechanism or
configuration for tuning machinery is introduced.

## Add a regional cluster (`mode=cluster` or `mode=combined`)

Helm renders the regional connector: its account, RBAC, configuration,
Deployment and an empty cluster credential Secret. There is no installer Job.

1. In the console, issue a cluster bootstrap (Fleet). Note the receipt's
   cluster ID and peer ID.
2. Read the bootstrap record from the bootstrap KV channel with your own
   OpenBao access and store it as `bootstrap.json` in a Secret in the release
   namespace. The record is valid for five minutes and works once.
3. Install or upgrade the release in the workload cluster.

```sh
kubectl --context REGION -n asservat-region create secret generic operator-bootstrap --from-file=bootstrap.json
helm upgrade --install asservat ./charts/asservat --kube-context REGION -n asservat-region \
  --set mode=cluster --set region.enabled=true \
  --set image.repository=REGISTRY/asservat --set image.digest=sha256:DIGEST \
  --set region.clusterID=CLUSTER_ID --set region.peerID=PEER_ID \
  --set region.bootstrapSecret=operator-bootstrap \
  --set-file region.offer=regional-offer.json \
  --set region.executor.evidenceSecret=operator-evidence
```

`regional-offer.json` is the hub's public regional offer. With an offer that
names the regional executor, `region.executor.evidenceSecret` names an existing
Secret with `evidence-storage.json` (write-only evidence capability) and
`history-storage.json` (history-prefix capability).

The connector seeds `<name>-cluster-credential` from the record once and then
rotates the credential itself; Helm keeps that Secret on upgrade and
uninstall. Exclude its data from GitOps diffs. After enrollment the bootstrap
record Secret can be deleted. If the record expires first, issue a new
bootstrap, replace the record, empty the credential Secret and restart the
connector.

With `mode=combined` (one cluster for hub and workloads, for example a
homelab) the connector runs in the hub's release namespace, reads the hub's
offer ConfigMap (`region.offerConfigMap`, default `<name>-regional-offer`) and
dials the in-cluster Services of federation, hub-api and key service
(`region.hub.*` override the defaults). It uses the generated
`<name>-s3-regional-write` and `<name>-s3-regional-history` Secrets. Steps 1
and 2 are the same; `region.offer` stays empty.

Regional options under `region.executor`:

- `alertmanager` ([ADR-231](../decisions/231-alert-detector.md)): the cluster's
  Alertmanager base URL for alert policies, for example
  `http://alertmanager-operated.monitoring.svc:9093`. The connector sends
  unauthenticated `GET /api/v2/alerts` requests and follows no redirect.
- `identityMappings` ([ADR-245](../decisions/245-decision-time-permission-sources.md)):
  records mapping the hub's principal to this cluster's OIDC identity
  (`usernamePrefix` + OIDC `sub`, optional `groupsPrefix` + stable group IDs).
  With records the connector account gets `create subjectaccessreviews`.
- `profileEndpoints` ([ADR-285](../decisions/285-profile-preview-plans.md)) and
  `profileAuthorization` (adds `profile-authorization.json` from the evidence
  Secret).

Log and resource DebugPolicies
([ADR-241](../decisions/241-log-resource-detectors.md)) use the connector's
`get pods/log` and `list pods.metrics.k8s.io`; resource policies need the
metrics API.

## Node collector (test hosts only)

[ADR-246](../decisions/246-node-collector-role.md) adds the `collector` values.
They are off by default, require `region.enabled` and are for disposable test
environments only:

- `collector.namespace` (default `asservat-collector`) is created with
  `pod-security.kubernetes.io/enforce|audit|warn: privileged`. Workload
  namespaces are not touched.
- The DaemonSet runs `/asservat node` from `image` (built with the `gadget`
  tag) as root without `privileged`, with the capabilities listed in the
  template, host PID and read-only mounts of the guard file, debugfs, tracefs
  and bpffs. Its projected token has the audience `asservat-node:<clusterID>`.
- The connector generates its node listener pair once into
  `<name>-connector-nodes` and publishes the issuing root into
  `<name>-node-connector-ca` in the collector namespace; collector Pods start
  once that root exists.
- `collector.ceilings` are the per-node ring, frozen, upload-rate and burst
  ceilings; the container memory limit is ring + frozen + 128 MiB.

The kubelet starts a collector Pod only on a host with
`/etc/asservat-disposable-host`. Never create that file on a workstation or
shared cluster node; kind nodes share their host's kernel.

## Production packaging contract

| Concern | Required behavior when runtime roles are introduced |
| --- | --- |
| Topology | One hub release in the management cluster; repeatable cluster enrollment without inbound node access; combined mode for evaluation |
| Identity and secrets | External OIDC or local accounts; separate browser/MCP/service clients. Stable Secret references; a scoped one-time bootstrap may create secrets outside Helm release data. No default passwords or upgrade-time regeneration |
| Dependencies | Explicit small or external profile, independently selectable identity/key/database/store providers. Bundled PostgreSQL required; SeaweedFS and pgBackRest selected pending qualification. No hidden service/operator/broker installation |
| Isolation | Separate runtime identities, bounded resources, control/analysis Restricted pods; explicitly opted-in privileged collector namespace; no changes to workload namespaces |
| Optional features | No core interception by default; encrypted analysis scratch prerequisite; unavailable optional mechanisms explain their remedy without disabling qualified context collection |
| Lifecycle | CRD upgrade before dependent code; explicit one-shot SQL migrator identity; current/previous compatible readers; rollback only when schemas permit |
| Configuration | Closed values schema, generated canonical CRDs, private registry/digest support, protected namespace and immutable installation/enrollment pins |
| Availability | Role-specific probes, replicas, leases/fencing, disruption policy, capacity and fair queues; successful Helm installation is distinct from collection readiness |
| Removal | Drain admission/recorders, preserve custody/audit/obligations, keep deletion workers until copies are verified gone; never delete CRDs/SQL/evidence automatically in an uninstall hook |
| Air gap | Local chart archive and complete verified image/tool bundle; no runtime internet lookup, update check, CDN, telemetry or registry fallback |

## Planned small profile

The accepted [dependency recommendations](../research/small-deployments.md) select local accounts/OAuth, an isolated static-key service, one PostgreSQL instance with pgBackRest and one SeaweedFS instance on persistent storage. These choices add no separately operated SSO/KMS/S3 service. They preserve TLS, encryption, role separation, native downloads, workload allocations and administrator retention caps. Small mode can manage multiple clusters; it is independent of the topology value. Each dependency can be replaced separately with a qualified external service.

The [small-profile candidate guide](small-profile.md) and [site values overlay](../../examples/helm/small-profile-values.yaml), merged after the finite context-trial profile, now select bundled PostgreSQL/pgBackRest, OpenBao, SeaweedFS and Keycloak. They document source image builds, storage/backup failure domains, single-instance downtime, retained state and the first operator workflow. Complete all four bundled services installed qualification and restore remain pending; the static-key alternative is unfinished. Optional offline analysis remains unavailable until encrypted scratch is qualified. Keep `runtime.enabled: false`: the explicit bootstrap continuation provisions the selected runtime. REQ-DEP-001–005 and TASK-11 track the broader work.

## Verification

`make helm-check` validates defaults and all topology modes, strict schema rejection, disabled-runtime rendering guard, Kubernetes lower bound, canonical CRD inclusion and local packaging. It uses the existing Python validation environment and the Helm executable; no Helm plugin is required.

`make helm-integration` owns a disposable Kind cluster with a pinned node image. It applies CRDs with the documented field manager, installs the packaged chart, checks structural CRDs against the API, creates synthetic configuration, upgrades a changed schema/chart version without forcing ownership, and verifies rollback/uninstall preserve CRDs and custom-resource UIDs. It never installs a collector or changes a workstation kernel setting. Results are recorded under `test/results/helm-*`. Qualification is limited to versions in the actual environment report; no production install or complete debugging workflow is implied.

Local qualification passed on 2026-10-10 with Helm **4.3.0** and Kubernetes **1.37.0**, recorded in [the environment report](../../test/results/helm-environment.json) and [run log](../../test/results/helm-integration.log). Source hashes were unchanged and cleanup completed. All three modes passed. Helm-created CRDs were separately tested in `helm-third-*`; the recommended explicit first apply also tested a changed schema version. Earlier failed runs in `helm-first-*` and `helm-second-*` exposed an empty `required` array that the API omits, causing an unchanged-schema SSA conflict. The generator now omits that semantically empty array. No forced ownership or weaker schema validation was used.

## Research and choices

Reviewed on 2026-10-10: [Helm's CRD lifecycle](https://helm.sh/docs/chart_best_practices/custom_resource_definitions/) explains why the chart keeps CRDs in `crds/` and requires explicit updates. [Chart structure and values schemas](https://helm.sh/docs/topics/charts/) support local archives and schema validation; that page warns that parts are not updated for Helm 4, so executable checks establish behavior for the installed version. [OCI distribution](https://helm.sh/docs/topics/registries/) is the selected publication format once release publication is authorized. No new templating framework, operator or chart-testing plugin is introduced.
