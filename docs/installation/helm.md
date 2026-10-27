# Install Asservat with Helm

Helm is the official installation and upgrade path. The [chart README](../../charts/asservat/README.md) contains the runnable commands and complete values table for the current package. The [operations contract](../operations.md) describes the eventual runtime profiles. TASK-11, REQ-UX-001 and REQ-ARC-001 cover installation ergonomics and role isolation.

## Current scope

Version `0.1.0-dev.1` packages AccessBinding, PermissionSource, EvidenceRetentionPolicy and CapacityReservation structural CRDs, plus a nonauthorizing release inventory. All three topology modes are accepted. By default, no runtime Deployment, collector, public route, database migration, default permission grant or baseline policy is installed. The optional ADR-137 bootstrap hook packages initial schema and activation. Explicit runtime continuation adds its final command to the same fixed runner Pod. The earlier bootstrap/private-registry composition has native evidence; this consolidated layout awaits separate qualification. Default policies must be protected and accepted by the runtime before becoming authoritative; rendering a policy does not establish acceptance.

The initial external identity provider is **Keycloak**, selected by the maintainer. Reuse the [qualified reference profile](../architecture/keycloak-profile.md) for its browser/MCP implementation; issuer/client/group configuration remains independently protected. The maintainer subsequently required an internal users/login option and small-deployment alternatives under [ADR-063](../decisions/063-small-deployment-alternatives.md). Those are planned features; the current chart does not provide them. Do not auto-install a realm, embed an administrator password or infer authority from group display names. Keycloak token integration is already tested; complete browser/MCP sign-in and installer acceptance remain in progress.

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
the native public projection. Leave `probeAudience` empty only when the current
projected API token has one audience; set it explicitly for ambiguous profiles.

After the references and public values exist, the fresh operation is one Helm
invocation (apply/upgrade the CRDs separately as documented):

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

## Add a regional cluster (`mode=cluster`)

[ADR-193](../decisions/193-installed-federation-and-regional-enrollment.md)
installs one regional connector per workload cluster. It needs three inputs:

1. **The hub's offer.** Copy `regional-offer.json` from the hub's
   `asservat-<installation>-regional-offer` ConfigMap. It is public.
2. **A bootstrap record.** A fleet operator issues a bootstrap slot. Read its
   record from the bootstrap KV channel with your own OpenBao access, and
   store it as `bootstrap.json` in a Secret in the release namespace. The
   record is valid for five minutes and works once; never put it in values.
3. **The product image**, pinned by digest.

```sh
kubectl --context REGION create secret generic operator-bootstrap   --namespace asservat-region --from-file=bootstrap.json
helm upgrade --install asservat oci-or-path/asservat --kube-context REGION   --namespace asservat-region --set mode=cluster --set cluster.enabled=true   --set cluster.image=REGISTRY/asservat@sha256:DIGEST   --set cluster.bootstrapSecret=operator-bootstrap   --set-file cluster.offer=regional-offer.json
```

The post-install hook runs `asservat installer-cluster --in-cluster`. It
creates the connector namespace (default `asservat-connector`), the account,
its RBAC, the Deployment at zero replicas, both guards, the source, the
generation-0 credential Secret and `regional-inputs`. The release's installer
account becomes the guards' administrator. The connector is ungated only
after both guards are proven with its own token. It then enrolls in-band with
the hub. Upgrades rerun the hook, which reopens identical objects and changes
nothing. A failed hook prints its installer step and a closed cause. The
installer account is the only administrator of the connector objects; even a
cluster administrator's writes there are denied, so change them with
`helm upgrade`.

Without Helm, run the same command from a workstation, where the guard
administrator is your own identity. Apply the matching chart's CRDs in the
regional cluster before issuing the five-minute bootstrap record, using the
[existing administrator-owned CRD workflow](../../charts/asservat/README.md#install-the-current-foundation).
From this source checkout:

```sh
kubectl --context REGION apply --server-side \
  --field-manager=asservat-crd-upgrade -f ./charts/asservat/crds
kubectl --context REGION wait --for=condition=Established --timeout=60s \
  crd/capacityreservations.asservat.io
```

After obtaining the bootstrap record:

```sh
asservat installer-cluster --context REGION --offer regional-offer.json   --bootstrap bootstrap.json
```

An offer containing context execution requires the namespaced
`CapacityReservation` API and its status subresource. The installer checks
that the API is served before creating installation resources and reports
`start-api` if the prerequisite is unavailable. This bounded discovery check
does not validate the CRD schema or confer runtime authority. The operator
or Helm retains CRD ownership; the installer creates or adopts no CRDs.

Alert DebugPolicies ([ADR-231](../decisions/231-alert-detector.md)) read the
cluster's own Alertmanager. To enable them, add
`--set cluster.alertmanager=http://alertmanager-operated.monitoring.svc:9093`
(or `installer-cluster --alertmanager URL`) with an executor offer. The
connector sends unauthenticated `GET /api/v2/alerts` requests to that address;
it follows no redirect and sends no credential. Alert rules must label alerts
with the Pod's `namespace` and `pod`. The address is a fixed regional input:
choose it at installation. Without it, activating an alert policy on that
cluster is refused with `DetectorUnavailable`.

Log and resource DebugPolicies ([ADR-241](../decisions/241-log-resource-detectors.md))
need no installer option. The connector's ClusterRole includes `get` on
`pods/log` and `list` on `pods.metrics.k8s.io` (the cluster-installer role holds
both so that it may grant them). A log policy reads the container logs of its
own workload's Pods only while it is active, and only match counts and times
leave the cluster. A resource policy needs the Kubernetes metrics API, normally
served by [metrics-server](https://github.com/kubernetes-sigs/metrics-server):
without it, activation is refused with `DetectorUnavailable`. A connector
installed by an earlier release lacks these permissions until it is installed
again, and its log and resource polls stay Unknown.

Exec and access-review inheritance ([ADR-245](../decisions/245-decision-time-permission-sources.md))
needs an identity mapping record on the workload cluster, named by the
PermissionSource's `identityMappingRef`:

```yaml
cluster:
  identityMappings:
    - name: company-oidc-to-cluster
      issuer: https://identity.example.invalid/realms/company
      usernamePrefix: "oidc:"   # the cluster's --oidc-username-prefix; the user is prefix + OIDC sub
      groupsPrefix: "oidc:"     # omit to send no groups; groups are the stable group IDs
```

The record must match the cluster's own OIDC authenticator (username from the
`sub` claim, groups from the stable group IDs Asservat receives). Display names
and e-mail are never used. With records configured the connector account gets
`create subjectaccessreviews`; it reviews only the authenticated user of a
request for the exact Pod (or the configured workload/namespace check) and
returns only the outcome. Like the Alertmanager address it is a fixed regional
input (executor offer only). Without a matching record, decision-time sources
of that cluster grant nothing.

The regional cluster needs outbound HTTPS to the federation endpoint in the
offer. The hub operator can pin the federation's node port with
`federation.nodePort` so the endpoint is known before installation. If the
bootstrap expires before the connector enrolls, issue a new one, delete the
connector namespace and install again.

## Node collector (test hosts only)

[ADR-246](../decisions/246-node-collector-role.md) adds the `collector` values (S-04 increment 3).
They are off by default and are for the disposable S-04 test environment only:

- `collector.namespace` (default `asservat-collector`) is created with
  `pod-security.kubernetes.io/enforce|audit|warn: privileged`. It must differ from the release,
  connector, `default` and `kube-*` namespaces. Workload namespaces are not touched.
- The DaemonSet runs `/asservat node` from the exact `collector.image` digest (built with the
  `gadget` tag) as root without `privileged`, with `BPF`, `NET_ADMIN` and `SYS_RESOURCE`, host PID,
  runtime-default seccomp/AppArmor and read-only mounts of the guard file, debugfs, tracefs and
  bpffs. The collector account has no RBAC binding; its projected token has the audience
  `asservat-node:<installationID>`.
- `collector.connector` names the connector's node listener (port 8444), its certificate server
  name and PEM roots. With `mode=cluster` and `cluster.enabled` in the same release, leave all
  three empty: the cluster installer hook then provisions the listener (Secret, Service and the
  attestation reads) and publishes the values in the ConfigMap `connector-nodes` of
  `cluster.namespace`, which the chart reads through `lookup`. The hook runs after the first
  render, so `helm install` creates only the collector namespace and account; run the same
  `helm upgrade` once afterwards to start the DaemonSet. Enable the collector together with the
  connector: adding it later changes the connector's fixed inputs and needs a connector
  reinstall. With the operator CLI (`installer-cluster --collector-namespace <ns>
  --collector-name <release>-node`, collector namespace created first) or `mode=combined`, copy
  `.Nodes` from the installer output (or the ConfigMap's `endpoint`, `serverName`, `rootsPEM`)
  into these values.
- `collector.ceilings` are the per-node ring, frozen, upload-rate and burst ceilings; the
  container memory limit is ring + frozen + 128 MiB.

The kubelet starts a collector Pod only on a host with `/etc/asservat-disposable-host`. Never
create that file on a workstation or shared cluster node; kind nodes share their host's kernel.

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

The installation must explain storage/backup failure domains and single-instance downtime, preserve data/keys on uninstall, and report optional offline analysis unavailable until encrypted scratch is qualified. No concrete `small` values file is shipped yet: add closed schemas, actual consumers, first-party templates and lifecycle/restore tests together. The foundation chart still rejects runtime enablement. REQ-DEP-001–005 and TASK-11 track the work.

## Verification

`make helm-check` validates defaults and all topology modes, strict schema rejection, disabled-runtime rendering guard, Kubernetes lower bound, canonical CRD inclusion and local packaging. It uses the existing Python validation environment and the Helm executable; no Helm plugin is required.

`make helm-integration` owns a disposable Kind cluster with a pinned node image. It applies CRDs with the documented field manager, installs the packaged chart, checks structural CRDs against the API, creates synthetic configuration, upgrades a changed schema/chart version without forcing ownership, and verifies rollback/uninstall preserve CRDs and custom-resource UIDs. It never installs a collector or changes a workstation kernel setting. Results are recorded under `test/results/helm-*`. Qualification is limited to versions in the actual environment report; no production install or complete debugging workflow is implied.

Local qualification passed on 2026-10-10 with Helm **4.3.0** and Kubernetes **1.37.0**, recorded in [the environment report](../../test/results/helm-environment.json) and [run log](../../test/results/helm-integration.log). Source hashes were unchanged and cleanup completed. All three modes passed. Helm-created CRDs were separately tested in `helm-third-*`; the recommended explicit first apply also tested a changed schema version. Earlier failed runs in `helm-first-*` and `helm-second-*` exposed an empty `required` array that the API omits, causing an unchanged-schema SSA conflict. The generator now omits that semantically empty array. No forced ownership or weaker schema validation was used.

## Research and choices

Reviewed on 2026-10-10: [Helm's CRD lifecycle](https://helm.sh/docs/chart_best_practices/custom_resource_definitions/) explains why the chart keeps CRDs in `crds/` and requires explicit updates. [Chart structure and values schemas](https://helm.sh/docs/topics/charts/) support local archives and schema validation; that page warns that parts are not updated for Helm 4, so executable checks establish behavior for the installed version. [OCI distribution](https://helm.sh/docs/topics/registries/) is the selected publication format once release publication is authorized. No new templating framework, operator or chart-testing plugin is introduced.
