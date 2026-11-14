# Install Asservat with Helm

> **Target workflow.** This page describes the target chart of [ADR-335](../decisions/335-usable-by-default.md) and ADR-334; the chart implements it in slices tracked in the [implementation ledger](../implementation-progress.md).

Helm is the only installation and upgrade path. This page is the reference:
what the chart installs, which values to set and how to install, upgrade,
back up, restore and remove a release. For step-by-step walkthroughs, use one
of these:

- [Quick trial with bundled services](small-profile.md): one cluster, every
  service in the chart.
- [Install with external services](context-trial.md): your own PostgreSQL,
  object store, OpenID Connect provider and, optionally, OpenBao.

**No supported release exists.** Until one does, build the images from source
and push them to your own registry.

## What the chart installs

Helm renders every Kubernetes object, including the CRDs. Two Jobs do the
work that needs live state:

1. **`<name>-secrets`** (pre-install and pre-upgrade hook) creates each missing
   generated Secret and never changes an existing value. Its Role can only
   create Secrets and get or patch the named ones.
2. The selected bundled services start: PostgreSQL with pgBackRest, SeaweedFS,
   the local key service and, if selected, Keycloak.
3. **`<name>-setup-<hash>`** waits for PostgreSQL, applies the schema, creates
   or updates the runtime SQL roles, reconciles the bundled Keycloak realm and
   object store, initializes processing from the values and applies requested
   credential rotations. Every step is idempotent. The hash covers the chart
   version, image and values, so every change runs it once.
4. Hub workloads wait in a `wait-schema` init container until the schema is
   current, then start.

The CRDs are templates annotated `helm.sh/resource-policy: keep`, so
`helm upgrade` upgrades them and `helm uninstall` leaves them. Set
`crds.install: false` if you manage them separately.

`<name>` is `installation.name` (default `asservat`). The
[chart README](../../charts/asservat/README.md) lists every value and generated
Secret. Every value can change on `helm upgrade`; nothing is fixed at the
first install. The values schema refuses settings a component would reject.

## Prerequisites

- Kubernetes 1.30 or newer, Helm and kubectl.
- A default StorageClass, or `storageClass` set for each bundled service. The
  defaults request 64 GiB PostgreSQL data, 64 GiB local backup and 32 GiB
  SeaweedFS.
- One DNS name for the console, with a way to reach it: an Ingress controller,
  a Gateway API implementation, or a NodePort or LoadBalancer Service. A
  serving certificate for it, from cert-manager or an existing TLS Secret.
- An identity provider: bundled Keycloak, or an OpenID Connect provider you
  run.

The release namespace may be created with `--create-namespace`. Every chart
Pod satisfies Pod Security `restricted`; labelling the namespace with it is
recommended. The node collector runs in its own namespace (see
[Node collector](#node-collector)).

## Minimal values

A working single-cluster installation (`mode: combined`, the default) needs
only the origin, the exposure and the identity provider:

```yaml
origin: https://asservat.example.org
exposure:
  ingress:
    enabled: true
    className: nginx
    tls: {secretName: asservat-tls}
services:
  identity:
    provider: keycloak
administrators:
  groups: [asservat-admins]
```

With these, the chart runs bundled PostgreSQL, SeaweedFS and the local key
service; captures, the node collector, approvals and sign-in work after the
first `helm install`.

## Choose bundled or external services

Each service is selected on its own under `services`. Bundled services run in
the release namespace and get generated credentials.

| Service | Default | Alternatives |
| --- | --- | --- |
| PostgreSQL | `services.postgres.provider: bundled` | `external`; see [External PostgreSQL](#external-postgresql) |
| Object store | `services.objectStore.provider: seaweedfs` | `external`; see [External object store](#external-object-store) |
| Key service | `services.keyService.provider: local` (static keys in generated Secrets) | `openbao` (bundled) or `external`; see [External OpenBao](#external-openbao) |
| Identity | none; you choose | `keycloak` (bundled) or `external`; see [External Keycloak](#external-keycloak) |

External services are never provisioned or adopted by the chart beyond the
setup steps named in their sections. Connections to them use the system trust
store; set `services.<service>.external.caBundle` (`identity.caBundle` for
the identity provider) only for a private CA.

## Identity and administrators

- `origin` is the browser URL of the console and API.
- `services.identity.provider: keycloak` derives the issuer and clients from
  the bundled realm. With an external provider set `identity.issuer`,
  `identity.clientID` and `identity.clientSecret.existingSecret`.
- `identity.groupsClaim` (default `groups`) names the token claim that
  carries group names. Bindings name groups as the provider emits them.
- `administrators.groups` and `administrators.subjects` list the
  installation administrators. They hold every administrative right,
  including privacy processing and cluster registration.
- Everyone else who can sign in at the issuer and client may sign in, and
  gets rights only through AccessBindings, ClusterAccessBindings or
  PermissionSources (see [Grant teams access](#grant-teams-access)).

There is no installation-wide session limit; sign-in is rate-limited per
client and subject.

Never put passwords, tokens, client secrets or private keys in values. Helm
stores values in its release Secret.

## Expose the console

hub-api serves the console on Service `<name>-hub-api`, port 9445. Choose one:

- **Ingress**: `exposure.ingress.enabled: true`, `className`, controller
  `annotations` and `tls.secretName`, or `tls.certManager.issuerRef` to let
  cert-manager issue the certificate.
- **Gateway API**: `exposure.httpRoute.enabled: true` with `parentRefs`.
- **NodePort or LoadBalancer**: `exposure.service.type` (and `nodePort`), with
  `exposure.tlsSecret`, an existing `kubernetes.io/tls` Secret; hub-api then
  terminates TLS itself.

With an Ingress or HTTPRoute the proxy terminates TLS and the host comes from
`origin`. The chart adds no controller-specific annotations. Bundled Keycloak
is served under `<origin>/idp` on the same Ingress or HTTPRoute (with Service
exposure, through `services.identity.keycloak.service`); hub-api reaches it
through its in-cluster Service. Workload-cluster connectors use the
same URL (see [Workload clusters](#workload-clusters)); no other port is
exposed.

## Install

```sh
helm upgrade --install asservat ./charts/asservat \
  --namespace asservat-system --create-namespace -f site-values.yaml \
  --wait --wait-for-jobs --timeout 15m
```

The command returns once setup has completed and the workloads are ready.
setup initializes processing from the `processors` values, so captures work
without a console step. The release NOTES print the console URL and, with bundled Keycloak, the command
that reads the bootstrap administrator's password.

## Bundled Keycloak

The `secrets` hook generates the bootstrap administrator, the console client
secret and the realm's group IDs once into `<name>-keycloak-state`. setup
reconciles the realm on every run through the Keycloak admin API: clients,
redirect URIs, scopes and the groups `asservat-users` and `asservat-admins`.
Changing `origin`, `services.identity.keycloak.realm` or the MCP redirect URIs
takes effect on the next `helm upgrade`.

Create users in one of two ways:

- `services.identity.keycloak.initialUsers: [{username: alice, groups: [asservat-admins]}]`
  creates each user with a generated one-time password in
  `<name>-keycloak-users`; the user changes it at first sign-in.
- Sign in at `<origin>/idp/admin/` as the bootstrap administrator and manage
  users and group memberships there.

## External Keycloak

Set `services.identity.provider: external` and configure the realm as the
[Keycloak profile](../architecture/keycloak-profile.md) describes:

1. Create a confidential console client, for example `asservat-console`, with
   the authorization code flow and PKCE method S256. Disable direct access
   grants, implicit flow and service accounts.
2. Set its redirect URI to `<origin>/auth/callback`.
3. Add an audience mapper that puts the client ID (or
   `identity.browserAudience`) into access tokens.
4. Add a Group Membership mapper to the claim `groups` with full group path
   off.
5. Store the client secret in a Secret and set
   `identity.clientSecret.existingSecret` (key `client-secret`).

Other OpenID Connect providers (Entra ID, Okta, Google, Authentik) work the
same way with their standard groups claim; set `identity.groupsClaim` if it is
not called `groups`.

## External PostgreSQL

Set `services.postgres.provider: external` with `host`, `port` and
`database`. The server must accept TLS 1.2 or newer with a certificate valid
for `host`. The chart's pool defaults total at most 30 connections.

Choose how the logins are created:

- **setup creates them.** `adminSecret` names a Secret whose key
  `credentials.json` holds `{"username": "…", "password": "…"}` for a login
  with `CREATEROLE` that can create the schema objects. Only the setup Job
  mounts it. setup creates one login per process with the generated
  `<name>-sql-*` passwords and never drops a role.
- **You create them.** Create the migration owner and one login per process
  (`hub-api`, `hub-worker`, `key-service`, `download-reader`) as the chart
  README lists, and reference their Secrets under
  `services.postgres.external.logins`. No administrator credential is stored.

Bundled Keycloak on external PostgreSQL also needs
`services.identity.keycloak.database.host` and `credentialsSecretName`.

## External object store

Set `services.objectStore.provider: external` with `endpoint`, `region`,
`bucket` and optional `prefix`. Create the bucket with an
`AbortIncompleteMultipartUpload` lifecycle rule, then give Asservat one
credential limited to that bucket and prefix:

- a Secret named in `services.objectStore.external.existingSecret`, key
  `credentials.json`, holding `{"accessKeyID": "…", "secretAccessKey": "…"}`;
  or
- the platform's workload identity (IRSA, GKE or Azure Workload Identity):
  set `services.objectStore.external.ambientCredentials: true` and annotate
  the ServiceAccounts through `serviceAccount.annotations`.

setup creates no buckets or identities in an external store.

## External OpenBao

OpenBao is optional; the default local key service covers every purpose.
OpenBao, bundled or external, wraps artifact keys with one transit key named
after `installation.name`.

Only the regional reader's ServiceAccount logs in to OpenBao: it wraps keys
for new evidence and unwraps them for authorized reads; the hub and the
collectors never hold an OpenBao token.

Set `services.keyService.provider: external` with `endpoint`. Then either give
setup an admin token once in the Secret named by
`services.keyService.external.setupTokenSecret` (key `token`) and delete the
Secret after the install, or create the objects yourself (`asservat` is
`installation.name`, `asservat-system` the release namespace):

```sh
bao secrets enable -path=asservat-transit transit
bao write -f asservat-transit/keys/asservat-artifacts
bao policy write asservat-artifacts - <<'EOF'
path "asservat-transit/encrypt/asservat-artifacts" { capabilities = ["update"] }
path "asservat-transit/decrypt/asservat-artifacts" { capabilities = ["update"] }
EOF
bao write auth/kubernetes/role/asservat-artifacts \
  bound_service_account_names=asservat-download-reader \
  bound_service_account_namespaces=asservat-system \
  audience=openbao policies=asservat-artifacts token_ttl=1h
```

This assumes a Kubernetes auth method at `auth/kubernetes` for the hub
cluster. Runtime Pods log in with their projected ServiceAccount token.

## Capacity and retention

Capacity and retention defaults work without values. Change them on any
`helm upgrade`; they take effect at once.

| Value | Default | Meaning |
| --- | --- | --- |
| `capacity.evidenceStorage` | the bundled object store's volume size | Evidence storage Asservat may use; required for an external store |
| `capacity.workloadShare` | `2%` | Storage protected for each workload; a quantity or a share of `evidenceStorage` |
| `capacity.workloadLimit` | `10%` | Most a single workload may use, protected share plus shared burst |
| `capacity.capturesPerCluster` | larger of 8 and the node count | Concurrent captures per cluster |
| `retention.evidence`, `retention.cores` | `14d` | Default retention |
| `retention.maximum` | the longest default | Administrator maximum; requests beyond it are refused. Shares last until their evidence's retention ends |

The default budget policy covers every namespace except system namespaces,
the release namespace and namespaces labelled `asservat.io/evidence: disabled`.
Access still requires an AccessBinding. Lowering a limit below current use
blocks new captures there; it never deletes evidence. For different storage
or teams, add EvidenceStoragePool and EvidenceBudgetPolicy objects
([capacity isolation](../../specs/capacity.md)).

## Upgrade and roll back

Run `helm upgrade` with the same command and changed values. hub-api rolls
with at least two replicas available and hub-worker hands over to its standby,
so the console stays up. Both Jobs run again and are idempotent, so Argo CD's
per-sync hooks are safe.

Migrations are expand/contract: the previous minor release runs on the
current schema, so `helm rollback` to it works. Rolling back further needs a
[restore](#restore). Workload clusters may run the hub's version or the
previous minor one.

## Rotate credentials

Generated Secrets are created once and never regenerated by a render. To
rotate one, list it with a generation number higher than the last:

```yaml
secrets:
  rotate:
    - {name: sql-hub-api, generation: 2}
    - {name: artifact-key, generation: 2}
```

setup issues a new version (altering the SQL role, or adding a key or audit
MAC version while old versions stay readable), and the Pods using it roll.
Changing `hub.<component>.tls.dnsNames` reissues the generated serving
certificate under the unchanged CA.

## Back up

Back up these together, off the cluster:

| Data | How |
| --- | --- |
| PostgreSQL (also holds bundled Keycloak) | pgBackRest: `services.postgres.bundled.backup.repository.s3` (`endpoint`, `bucket`, `prefix`, `existingSecret`), `schedule` (default daily) and `retention` (default `14d`). The local backup volume alone is not disaster recovery. External PostgreSQL: your provider's backups. |
| Evidence | The object store's replication, or Velero backups of the SeaweedFS volumes. |
| Generated Secrets | Every Secret labelled `asservat.io/generated: "true"`, for example with Velero or an encrypted `kubectl get secret -l … -o yaml`. Without the key and CA Secrets, evidence and backups cannot be opened. |
| OpenBao, when used | `bao operator raft snapshot save`. |
| Keycloak on its own database | `kc.sh export` of the realm. |

Each component reports the age of its last successful backup in
installation status and as the metric
`asservat_backup_last_success_timestamp_seconds` on `/metrics`; set
`metrics.serviceMonitor.enabled: true` for Prometheus Operator and alert on
it.

## Restore

Restore in this order:

1. The generated Secrets, then OpenBao if used.
2. The object store (replica or volumes).
3. PostgreSQL. Bundled: run the same `helm upgrade` with

   ```yaml
   recovery:
     enabled: true
     restorePoint: "2026-11-14T03:00:00Z"   # or "latest"
   ```

   The chart scales hub-api, hub-worker and the local connector to zero,
   restores PostgreSQL from the pgBackRest repository to that point and runs
   setup's recovery step. External: restore the database with your provider's
   tooling, then run the same upgrade with `recovery.enabled: true` and the
   restore time as `restorePoint`.
4. Keycloak's realm import, if Keycloak has its own database.
5. Run `helm upgrade` again without `recovery`.

The recovery step re-applies revocations and deletions recorded after the
restore point, sends restored grants, shares and pending approvals back for
review when the restore point is older than the latest state, ends all
sessions and connector leases, and recomputes usage from the object store
([persistence](../../specs/persistence.md#req-db-005--durability-outage-and-disaster-recovery)).
Nothing is served until it has finished; an interrupted step resumes on the
next run.

## Uninstall

`helm uninstall` keeps:

- the CRDs,
- the PVCs of bundled services,
- the Secrets created by the `secrets` hook, which carry no Helm ownership.

Evidence in the object store stays too. Erasing an installation is a separate,
explicit step. A later install with the same `installation.name` uses the
kept state, and existing AccessBindings take effect at once.

## Workload clusters

`mode` selects the topology:

- **`combined`** (default): hub and workload roles in one cluster and one
  release.
- **`hub`** plus one **`cluster`** release per workload cluster. Bundled
  services require `hub` or `combined`.

A workload cluster's connector authenticates with its own cluster's
ServiceAccount token (ADR-334); nothing is copied between clusters. Register
the cluster in the hub's values and run `helm upgrade` on the hub:

```yaml
clusters:
  - name: eu                                   # how people and policies name it
    issuer: https://eu-apiserver.example        # its ServiceAccount token issuer
    # jwks: '<kubectl --context eu get --raw /openid/v1/jwks>'  # if the hub cannot reach the issuer
```

Then install the workload cluster's release:

```sh
helm --kube-context eu upgrade --install asservat ./charts/asservat \
  -n asservat-system --create-namespace \
  --set mode=cluster --set hub.url=https://asservat.example.org \
  --wait --timeout 10m
```

The connector reaches the hub at `hub.url`, through the same Ingress or
Gateway as the console. It trusts the hub's certificate through the system
roots, or `hub.caBundle` for a private CA. The hub generates the cluster's ID
from its name and pushes its settings over the connection; changes need no
restart. Add clusters at any time.

If the hub can neither reach the issuer nor be given its JWKS, an
administrator issues a join token in the console or with the CLI (valid
24 hours). Pass it to the workload cluster's release as `join.token` together
with `join.caHash`; the connector uses it once to register its ServiceAccount
keys.

Removing a cluster from `clusters`, or setting `revoked: true`, closes its
connection and refuses its tokens.

### Regional connector options

Options under `region.executor`:

- `alertmanager` ([ADR-231](../decisions/231-alert-detector.md)): the cluster's
  Alertmanager base URL for alert policies, for example
  `http://alertmanager-operated.monitoring.svc:9093`. The connector sends
  unauthenticated `GET /api/v2/alerts` requests and follows no redirect.
- `identityMappings` ([ADR-245](../decisions/245-decision-time-permission-sources.md)):
  records mapping the hub's principal to this cluster's OIDC identity
  (`usernamePrefix` + OIDC `sub`, optional `groupsPrefix` + group names).
  With records the connector account gets `create subjectaccessreviews`.
- `profileEndpoints` ([ADR-285](../decisions/285-profile-preview-plans.md)) and
  `profileAuthorization` (`mode: cluster` only).

Log and resource DebugPolicies
([ADR-241](../decisions/241-log-resource-detectors.md)) use the connector's
`get pods/log` and `list pods.metrics.k8s.io`; resource policies need the
metrics API.

## Grant teams access

An AccessBinding lives in the application namespace it grants access to, like
a RoleBinding ([ADR-329](../decisions/329-accessbindings-in-application-namespaces.md)).
Its scope is that namespace, optionally narrowed to workloads by name; a
recreated Deployment of the same name keeps its access. A ClusterAccessBinding
grants a role in every namespace, like a ClusterRoleBinding.

```yaml
apiVersion: asservat.io/v1alpha1
kind: AccessBinding
metadata:
  name: payments-maintainers
  namespace: payments
spec:
  effect: Allow
  subjects:
    - {kind: Group, name: payments-team}
  roles: [workload-maintainer]
  # Optional: only these workloads of the namespace.
  # workloads: [{kind: Deployment, name: api}]
  # Optional: reason: Payments team maintainers
```

Subjects default to the installation's issuer. Existing bindings take effect
whenever the hub starts, including bindings applied before the chart.

Ordinary Kubernetes RBAC decides who writes them:

- The chart aggregates read access into the `view`, `edit` and `admin`
  ClusterRoles and write access into `admin`, so a namespace administrator
  manages that namespace's AccessBindings, as with RoleBindings.
- Like the RoleBinding `bind` check, a writer needs the `bind` verb on the
  virtual resource `accessroles.asservat.io` named after each role the binding
  grants (`evidence-reader`, `workload-maintainer`, `evidence-owner`,
  `action-approver`). `admin` includes it for all four. A narrower writer, for
  example a GitOps account that may grant only `evidence-reader`, gets a Role
  like this (`kubectl create role` does not accept the virtual resource):

  ```yaml
  apiVersion: rbac.authorization.k8s.io/v1
  kind: Role
  metadata: {name: asservat-readers, namespace: payments}
  rules:
    - {apiGroups: [asservat.io], resources: [accessbindings], verbs: [get, list, create, update, patch, delete]}
    - {apiGroups: [asservat.io], resources: [accessroles], resourceNames: [evidence-reader], verbs: [bind]}
  ```

- `spec.automation` (team policy delegation) additionally needs `bind` on
  `accessroles` named `automation`, which no aggregated role grants. An
  administrator binds `<release-namespace>-<name>-accessbindings-automation`
  in each namespace whose team may delegate policies:
  `kubectl -n payments create rolebinding payments-automation
  --clusterrole=asservat-system-asservat-accessbindings-automation --group=payments-admins`.
- The ValidatingAdmissionPolicy `<release-namespace>-<name>-accessbindings`
  enforces both checks on create and update. Deletion is not checked, as for
  RoleBindings: whoever may delete AccessBindings in a namespace can also
  remove a deny there.
- A binding the schema refuses grants and denies nothing; it does not stop the
  others.

A workload cluster needs no extra step: its release renders the same RBAC and
policy, and its connector delivers the cluster's bindings to the hub whenever
they change. If the connector cannot reach the hub, its last delivered
bindings stay in effect, allows and denies, until it delivers again. Teams
check a binding with `kubectl apply --dry-run=server` and their own access
with `explain_access`.

## Node collector

The node collector is on by default (`collector.enabled: true`):

- `collector.namespace` (default `asservat-collector`) is created with
  `pod-security.kubernetes.io/enforce: privileged`. Workload namespaces are
  not touched.
- The DaemonSet runs `/asservat node` as root without `privileged`, with the
  capabilities listed in the template, host PID and read-only mounts of
  debugfs, tracefs and bpffs. Its projected token has the audience of the
  local connector.
- `collector.nodeSelector` and `collector.tolerations` choose the nodes.
- `collector.ceilings` are the per-node ring, frozen, upload-rate and burst
  ceilings as Kubernetes quantities; the container memory limit is
  ring + frozen + 128 MiB.

Set `collector.enabled: false` where a privileged namespace is not allowed,
and on clusters whose nodes share a kernel with a workstation, such as kind.

## Troubleshoot

Read the Job logs first:

```sh
kubectl -n asservat-system logs job/asservat-secrets
kubectl -n asservat-system logs -l app.kubernetes.io/component=setup --tail=50
```

- **`secrets: <Stage> <Secret>; check the named Secret …`**: the hook could
  not create or read the named Secret, or an existing one has the wrong keys.
  It never prints values.
- **`setup stopped at <step> (<class>)`**: the step is, for example,
  `postgres/wait`, `schema`, `roles/<role>`, `keycloak/realm`,
  `openbao/login` or `objectstore/bucket`. The class is `invalid`, `denied`,
  `changed`, `deadline` or `unavailable`.
- **`retrying: … cause: …`**: setup retries an unreachable provider with
  backoff until the Job's `activeDeadlineSeconds` (`setup.activeDeadlineSeconds`,
  default 30 minutes).
- **Pods stuck in `Init`**: the `wait-schema` init container waits until setup
  applies the schema. Its log prints `schema <n> is current` when done.
  `setup stopped at schema (changed)` means the database is newer than the
  previous minor release supports; restore or upgrade the image.

Fix the values and run the same `helm upgrade`. Never delete generated Secrets
or retained PVCs to clear an error: the data they protect would no longer
open.

## Production packaging contract

| Concern | Required behavior |
| --- | --- |
| Topology | One hub release; workload clusters registered by name and ServiceAccount issuer, joined without copied Secrets or inbound node access; combined mode by default |
| Identity and secrets | External OIDC or bundled Keycloak with a reconciled realm; groups by name. Generated Secrets created once by the `secrets` hook outside Helm release data, `existingSecret` overrides, explicit rotation. No default passwords or render-time regeneration |
| Dependencies | Independently selectable identity, key, database and object-store providers with working defaults. No hidden service, operator or broker installation |
| Isolation | Separate runtime identities, bounded resources, Restricted control and analysis Pods; privileged collector confined to its namespace; no changes to workload namespaces |
| Optional features | No core interception by default; encrypted analysis scratch prerequisite; unavailable optional mechanisms explain their remedy without disabling context collection |
| Lifecycle | Templated CRDs with `keep`; idempotent setup; expand/contract schema with a one-minor rollback window; off-cluster backups and a tested `recovery` restore |
| Configuration | Closed values schema matching component bounds; every value changeable with `helm upgrade`; Kubernetes quantities for sizes |
| Availability | Role-specific probes; rolling hub-api with two replicas, leader-elected hub-worker with a standby; capacity and fair queues; a successful Helm install is distinct from collection readiness |
| Removal | Drain admission and recorders, preserve custody, audit and obligations, keep deletion workers until copies are verified gone; never delete CRDs, SQL or evidence in an uninstall hook |
| Air gap | Local chart archive and complete verified image bundle; no runtime internet lookup, update check, CDN, telemetry or registry fallback |
