# Install Asservat with Helm

Helm is the only installation and upgrade path. This page is the reference:
what the chart installs, which values to set and how to run, upgrade and
remove a release. For step-by-step walkthroughs, use one of these:

- [Quick trial with bundled services](small-profile.md): one cluster, all four
  services in the chart.
- [Install with external services](context-trial.md): your own PostgreSQL,
  S3, OpenBao and Keycloak.

**No supported release exists.** You build the images from source and push
them to your own registry. A fresh all-bundled `mode: combined` install passes
the full journey in `test/integration/helm_native_kind_test.go` on kind:
Keycloak sign-in, processing initialization, pod-status capture, inspection and
native download, and so does a second workload cluster joined with
`mode: cluster` (owned kind clusters). External providers are not qualified
with this chart yet. The
[implementation ledger](../implementation-progress.md) records actual results.

## What the chart installs

Helm renders every Kubernetes object. Two Jobs do the work that needs live
state:

1. **`<name>-secrets`** (pre-install and pre-upgrade hook) creates each missing
   generated Secret and never changes an existing value. Its Role can only
   create Secrets and get or patch the named ones.
2. The selected bundled services start: PostgreSQL with pgBackRest, OpenBao,
   SeaweedFS and Keycloak.
3. **`<name>-setup-<hash>`** (an ordinary Job) waits for PostgreSQL, applies the
   schema, creates or updates the runtime SQL roles and seeds the installation
   trust rows. With bundled OpenBao and SeaweedFS it also configures them. The
   hash covers the chart version, image and values, so every change runs it
   once.
4. Hub workloads wait in a `wait-schema` init container until the schema is
   current, then start.

`<name>` is `installation.name` (default `asservat`). The
[chart README](../../charts/asservat/README.md) lists every value and generated
Secret.

## Prerequisites

- Kubernetes 1.35 or newer, Helm and kubectl.
- A release namespace labelled with Pod Security `restricted`.
- A persistent StorageClass for bundled services. The defaults request 64 GiB
  PostgreSQL data, 64 GiB backup, 8 GiB OpenBao and 32 GiB SeaweedFS; these
  are settings, not measured minimums.
- A way to reach the console: an Ingress controller, a Gateway API
  implementation, or a NodePort or LoadBalancer Service.
- DNS names and serving certificates for the console origin and, if bundled,
  Keycloak. cert-manager works; the chart creates no certificates for them.
- Registry access from every node to the exact product image digest, and to
  the PostgreSQL image digest when PostgreSQL is bundled.

## Choose bundled or external services

Each service is selected on its own under `services`. Bundled services run in
the release namespace and get generated credentials.

| Service | Bundled | External |
| --- | --- | --- |
| PostgreSQL | `services.postgres.provider: bundled`, `bundled.image` (source-built) | `services.postgres.external`; see [External PostgreSQL](#external-postgresql) |
| Object store | `services.objectStore.provider: seaweedfs` | `services.objectStore.external`; see [External object store](#external-object-store) |
| Key service | `services.keyService.provider: openbao` | `services.keyService.external`; see [External OpenBao](#external-openbao) |
| Identity | `services.identity.provider: keycloak` | `identity.*`; see [External Keycloak](#external-keycloak) |

External choices are never provisioned or adopted by the chart. Each external
service needs its public CA bundle in `services.<service>.external.rootsPEM`
(`identity.providerRootsPEM` for the identity provider).

## Set origin, identity and exposure

### Origin and identity

- `origin` is the browser URL of the console and API, for example
  `https://asservat.example.org`.
- `identity.issuer`, `identity.clientID` and `identity.browserAudience` name the
  OpenID Connect provider, the console client and the access-token audience.
  With bundled Keycloak the issuer is `<hostname>/realms/<realm>`.
- `identity.eligibleGroups` or `identity.eligibleSubjects` list the stable
  issuer IDs allowed to sign in.
- `identity.processingOperators` lists at least one identity allowed to run
  processing initialization, as `{clientID, issuer, kind: Group|User, id}`.
- `fleet.clients` and `fleet.groups` (or `fleet.subjects`) allow cluster
  enrollment from the console.

Never put passwords, tokens, client secrets or private keys in values. Helm
stores values in its release Secret.

### Expose the console

hub-api serves the console on Service `<name>-hub-api`, port 9445. Choose one:

- **Ingress** (recommended): set `exposure.ingress.enabled: true`,
  `className`, controller `annotations` and `tls` blocks. Set
  `exposure.tls.mode: proxy` so the Ingress terminates TLS and forwards plain
  HTTP to hub-api.
- **Gateway API**: set `exposure.httpRoute.enabled: true` with `parentRefs`
  and `exposure.tls.mode: proxy`.
- **NodePort or LoadBalancer**: set `exposure.service.type` (and `nodePort`).
  Keep `exposure.tls.mode: pod`; hub-api then terminates TLS with
  `exposure.tlsSecret`, an existing `kubernetes.io/tls` Secret.

The Ingress and HTTPRoute take their host from `origin`, which must then carry
no port. The chart adds no controller-specific annotations.

The peer listeners stay `ClusterIP` in a single cluster: federation (9446),
key service (9447) and the hub-api native listener (9444). Only joined
workload clusters need them, and the evidence object store, reachable (see
[Join a workload cluster](#join-a-workload-cluster)), through
`hub.federation.service`, `hub.key-service.service`,
`hub.hub-api.nativeService` and `services.objectStore.seaweedfs.service` of
type `NodePort` or `LoadBalancer`. Route these as TCP; never terminate their
mTLS at an HTTP proxy. Their serving certificates come from
`hub.<component>.tls.existingSecret`, a cert-manager `issuerRef`, or a CA that
the `secrets` hook generates once.

## Install

Apply the CRDs, then install the release:

```sh
kubectl apply --server-side --field-manager=asservat-crd-upgrade \
  -f ./charts/asservat/crds
helm upgrade --install asservat ./charts/asservat \
  --namespace asservat-system -f site-values.yaml
kubectl -n asservat-system wait --for=condition=Complete --timeout=15m \
  job -l app.kubernetes.io/component=setup
```

A login page alone does not prove a complete installation; check that the
setup Job completed.

## Bundled Keycloak: read the generated IDs

With `services.identity.provider: keycloak`, the `secrets` hook generates the
realm into the Secret `<name>-keycloak-state`. It holds:

| Key | Content |
| --- | --- |
| `bootstrap-admin-username`, `bootstrap-admin-password` | Keycloak administrator |
| `console-client-secret` | Console client secret, used by hub-api |
| `users-group-id` | ID of group `asservat-users` |
| `<realm>-realm.json` | Imported realm, including group `asservat-processing-operators` when `services.identity.keycloak.processingOperators: true` |

These IDs exist only after the first install, so a bundled install takes two
passes. Install first with a placeholder `processingOperators` entry, then
read the IDs:

```sh
USERS=$(kubectl -n asservat-system get secret asservat-keycloak-state \
  -o jsonpath='{.data.users-group-id}' | base64 -d)
OPERATORS=$(kubectl -n asservat-system get secret asservat-keycloak-state -o json |
  jq -r '.data["asservat-realm.json"] | @base64d | fromjson
    | .groups[] | select(.name == "asservat-processing-operators") | .id')
```

Set `identity.eligibleGroups` and `fleet.groups` to `[$USERS]`, set
`identity.processingOperators` to the `$OPERATORS` group and run the same
`helm upgrade`. Each group carries its ID in the `asservat_group_id`
attribute; keep those attributes unchanged.

The bundled Keycloak Service `<name>-keycloak` serves HTTPS on 8443 as
`ClusterIP` or `NodePort`. `services.identity.keycloak.hostname` must be
reachable from browsers and from hub-api Pods. hub-api trusts the `ca.crt` of
`tlsSecretName`, or `identity.providerRootsPEM` when set.

## External Keycloak

Set `services.identity.provider: external` and configure the realm as the
[Keycloak profile](../architecture/keycloak-profile.md) describes:

1. Create a confidential console client, for example `asservat-console`, with
   the authorization code flow and PKCE method S256. Disable direct access
   grants, implicit flow and service accounts.
2. Set its only redirect URI to `<origin>/auth/callback`.
3. Add an audience mapper that puts `asservat-api` (your
   `identity.browserAudience`) into access tokens.
4. Add a multivalued User Attribute mapper from attribute `asservat_group_id`
   to claim `asservat_groups`, aggregated and in access tokens only. Protect
   the attribute against user edits.
5. Keep the built-in `basic` scope. Add default client scopes `evidence:read`,
   `evidence:download`, `evidence:capture` and `evidence:share`.
6. Store the client secret in a Secret and set
   `identity.clientSecret.existingSecret` (key `client-secret`).

Grant access by subject or by group:

- **Subjects**: put Keycloak user IDs (`sub`) into `identity.eligibleSubjects`
  or `fleet.subjects`, or use `kind: User` in `processingOperators`.
- **Groups**: give each group an `asservat_group_id` attribute with a stable,
  never reused ID (its Keycloak group UUID works). Put those IDs into
  `identity.eligibleGroups`, `fleet.groups` or `kind: Group` entries. Group
  names never grant access.

## External PostgreSQL

Set `services.postgres.provider: external` and `services.postgres.external`:
`host`, `port`, `database`, `rootsPEM` and `adminSecret`. The database must
exist and accept TLS 1.3 with a certificate valid for `host`.

`adminSecret` names an existing Secret whose key `credentials.json` holds
`{"username": "…", "password": "…"}`. Only the setup Job mounts it. The login
must be a superuser, or hold `CREATEROLE` and be able to create the schema
objects and grant on them. setup applies migrations with it and creates or
updates the runtime roles with the generated `<name>-sql-*` passwords. It
never drops a role. The bundled server allows 117 connections (122 with
bundled Keycloak); size an external server for at least that.

Bundled Keycloak on external PostgreSQL also needs
`services.identity.keycloak.database.host`, `credentialsSecretName` and
`rootsSecretName`.

## External object store

Set `services.objectStore.provider: external` and
`services.objectStore.external`: `endpoint`, `region`, `bucket` (audit
records), optional `evidenceBucket` (default: `bucket`) and `rootsPEM`.
setup does not create buckets or identities in an external store.

Create the buckets and one Secret `<name>-s3-<principal>` per principal, key
`credentials.json`, holding
`{"accessKeyID": "…", "secretAccessKey": "…", "sessionToken": ""}`. The
principals are `configuration-audit`, `owner-audit`, `federation-audit`,
`publisher-audit`, `publisher-read`, `download-read`, `evidence-delete`,
`operation-cleanup` and `operation-verify`, plus `regional-write` and
`regional-history` in `mode: combined`. Give each one only its own prefix and
actions; the bundled store's grants in
`internal/adapters/providerconfig/seaweed_storage.go` are the reference.

## External OpenBao

Set `services.keyService.provider: external` and
`services.keyService.external`: `endpoint` and `rootsPEM`. setup configures
only bundled OpenBao, so create these objects yourself. `<inst>` is the
installation ID from `<name>-ids` without dashes.

| Kind | Path |
| --- | --- |
| transit | `asservat-audit`, `public-transit` |
| pki | `owner-pki`, `connector-pki`, `worker-pki`, each with a root issuer |
| kv v2 | `fleet-bootstrap` |
| kubernetes auth | `asservat-configuration`, `asservat-owner`, both able to review tokens of the hub cluster |

Transit keys, never exportable: on `asservat-audit` the keys `audit`,
`asservat-<inst>-worker-configuration-audit`,
`asservat-<inst>-context-deletion` (ed25519),
`asservat-<inst>-federation-audit` and `asservat-<inst>-publisher-audit`; on
`public-transit` the keys `asservat-<inst>-browser-sessions` and
`asservat-<inst>-work-signing` (ed25519).

PKI roles: `asservat-<inst>-owner-server` and `-owner-client` on `owner-pki`,
`-connector-client` and `-connector-server` on `connector-pki`,
`-download-worker` and `-verifier` on `worker-pki`.

Each component purpose needs an ACL policy and a Kubernetes auth role, both
named `<name>-<component>-<purpose>`:

- On `asservat-configuration`: `hub-worker` with `audit-wrap`,
  `audit-unwrap`, `cleanup-wrap`, `cleanup-open`, `cleanup-verify` and
  `cleanup-sign`.
- On `asservat-owner`: `hub-api` with `audit-wrap`, `audit-unwrap`,
  `server-sign`, `client-sign`, `browser-seal`, `browser-open`, `work-sign`,
  `worker-issue` and `bootstrap-channel`; `federation` with `audit-wrap`,
  `audit-unwrap`, `client-sign` and `server-sign`; `publisher` with
  `audit-wrap`, `audit-unwrap` and `verifier-sign`.

Each policy grants the one transit or PKI operation of its purpose. The exact
PKI role bodies, token audiences and policy paths are in
`internal/adapters/providerconfig/setup_openbao.go`. This path is not
qualified yet.

## Upgrade, roll back and uninstall

Apply the CRDs first, then run `helm upgrade` with the same values. Both Jobs
run again; both are idempotent, so Argo CD's per-sync hooks are safe.
Configuration changes need no reinstall.

The schema only moves forward. A rollback keeps it and the generated Secrets;
an older image refuses a newer schema.

`helm uninstall` keeps:

- the CRDs in `crds/`, which Helm never deletes,
- the PVCs of bundled services,
- the Secrets created by the `secrets` hook, which carry no Helm ownership,
- the join Secrets `<name>-join-<cluster>` the hub-api creates,
- objects marked `helm.sh/resource-policy: keep`: `<name>-regional-offer`,
  `<name>-region-bootstrap`, `<name>-cluster-credential` and the
  `<name>-downloads` namespace.

Evidence in the object store stays too. Erasing an installation is a separate,
explicit step.

## Single cluster or separate workload clusters

`mode` selects the topology:

- **`combined`**: hub and workload region in one cluster and one release. Set
  `region.enabled: true`. hub-api issues the local connector's bootstrap
  itself into `<name>-region-bootstrap`; the connector reads the offer from
  `<name>-regional-offer` and dials the in-cluster Services. No NodePort or
  manual step is needed. Combined mode requires `federation.connector` and
  `capacity.backup`, which the
  [trial profile](../../examples/helm/context-trial-profile.yaml) supplies.
- **`hub`** plus one **`cluster`** release per workload cluster. Bundled
  services require `hub` or `combined`.

### Join a workload cluster

[ADR-331](../decisions/331-remote-cluster-join.md). Register the cluster in
the hub's values and expose the four endpoints its connector dials:

```yaml
clusters:
  - name: eu                 # DNS label; names the join Secret
    clusterID: 6f2d...       # a lowercase UUID you choose (uuidgen)
    # namespace: asservat-system   # its release namespace, default: the hub's
remote:
  federation: https://hub.example:9446    # -> <name>-federation:9446
  owners: hub.example:9444                # -> <name>-hub-api-native:9444
  keyService: https://hub.example:9447    # -> <name>-key-service:9447
  objectStore: https://hub.example:8333   # -> the evidence object store
federation:
  connector:
    profiles: 2   # every connector: the combined-mode one plus each cluster
    accounts: 2
```

Expose the federation (`hub.federation.service`), key service
(`hub.key-service.service`), hub-api native listener
(`hub.hub-api.nativeService`) and, with bundled SeaweedFS, the object store
(`services.objectStore.seaweedfs.service`) as `LoadBalancer`, `NodePort` or a
TLS-passthrough route. Connectors verify the in-cluster Service names, so the
serving certificates need no external name, and no proxy may terminate TLS in
front of them. `federation.connector` is fixed at the first install: size
`profiles` for every cluster you will join.

After `helm upgrade` of the hub, the hub-api creates the join Secret
`<name>-join-<cluster>` in the release namespace. It holds the cluster and
peer IDs, the offer, the cluster's object-store capabilities
(`<name>-s3-regional-write-<cluster>`, `-regional-history-<cluster>`, which
the secrets hook generates with bundled SeaweedFS; create them yourself for
an external store) and a one-use bootstrap record that is valid for five
minutes from issuance. Get a fresh record and copy it to the workload
cluster, then install there:

```sh
kubectl --context hub -n asservat-system delete secret asservat-join-eu --ignore-not-found
kubectl --context hub -n asservat-system wait --for=create secret/asservat-join-eu --timeout=60s
kubectl --context hub -n asservat-system get secret asservat-join-eu -o json \
  | jq '{apiVersion, kind, type, data, metadata: {name: .metadata.name}}' \
  | kubectl --context eu -n asservat-system apply -f -
kubectl --context eu apply --server-side --field-manager=asservat-crd-upgrade -f ./charts/asservat/crds
helm --kube-context eu upgrade --install asservat ./charts/asservat -n asservat-system \
  --set mode=cluster --set region.enabled=true --set region.joinSecret=asservat-join-eu \
  --set image.repository=<image> --set image.digest=<this chart version's digest>
```

The workload cluster's release uses its own chart version's image; it does
not need the hub's digest (see [version skew](#version-skew)). The connector seeds `<name>-cluster-credential` from the
record once and rotates it itself; keep the join Secret, which also carries
the offer. When the hub's offer changes, the hub-api updates its copy: copy
it again and restart the connector. A budget policy for the joined cluster
names its `clusterID` in `scope.clusterID`.

### Version skew

[ADR-333](../decisions/333-connector-version-skew.md). A workload cluster's
connector and node collectors may run one minor release older or newer than
the hub, as long as both speak the same connector protocol major (during 0.x
development, the protocol major is the boundary). Upgrade the hub first,
then each workload cluster at its own pace. Image digests are recorded as
provenance and are never compared.

The connector announces its protocol and capabilities when it connects. The
hub refuses a connector of another protocol major (hub-api log `context start
refused connector-protocol`) and refuses only the requests an older connector
lacks, with `connector too old for <capability>` (diagnostic step
`connector-too-old/<capability>`); everything else keeps working. Upgrade
that cluster's release to use the feature.

### Regional connector options

Options under `region.executor`:

- `alertmanager` ([ADR-231](../decisions/231-alert-detector.md)): the cluster's
  Alertmanager base URL for alert policies, for example
  `http://alertmanager-operated.monitoring.svc:9093`. The connector sends
  unauthenticated `GET /api/v2/alerts` requests and follows no redirect.
- `identityMappings` ([ADR-245](../decisions/245-decision-time-permission-sources.md)):
  records mapping the hub's principal to this cluster's OIDC identity
  (`usernamePrefix` + OIDC `sub`, optional `groupsPrefix` + stable group IDs).
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
Its scope is that namespace, optionally narrowed to named workloads; it names
no cluster or namespace UID. The hub-worker reads the hub cluster's
AccessBindings in every namespace. Cluster-wide or multi-namespace grants are
PermissionSources, which administrators keep in the release namespace.

```yaml
apiVersion: asservat.io/v1alpha1
kind: AccessBinding
metadata:
  name: payments-maintainers
  namespace: payments
spec:
  effect: Allow
  subjects:
    - kind: Group
      issuer: https://identity.example/realms/company
      id: payments-team-stable-group-id
  roles: [workload-maintainer]
  # Optional: only these workloads of the namespace.
  # workloads: [{kind: Deployment, name: api, uid: replace-with-the-uid}]
  reason: Payments team maintainers
```

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
- Each cluster's bindings share one bound of 1,024 AccessBindings and
  4,096 subject-role rows. A namespace can exhaust it for every namespace;
  limit object counts with a ResourceQuota on
  `count/accessbindings.asservat.io` where teams are not trusted with that.
- A binding the schema refuses grants and denies nothing; it does not stop the
  others.

A workload cluster joined with `mode: cluster` needs no extra step: its
release renders the same RBAC and policy, and its connector (with
`get/list/watch accessbindings`) delivers the cluster's bindings to the hub
whenever they change (a watch, at most once per second). A binding change
there takes effect at the hub within about a second. If the connector cannot
reach the hub, its last delivered bindings stay in effect, allows and denies,
until it delivers again. Each cluster has its own
1,024-binding and 4,096-row bound. The permission impact
preview is for fleet operators; teams check a binding with
`kubectl apply --dry-run=server` and their own access with `explain_access`.

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

## Troubleshoot

Read the Job logs first:

```sh
kubectl -n asservat-system logs job/asservat-secrets
kubectl -n asservat-system logs -l app.kubernetes.io/component=setup --tail=50
```

- **`secrets: <Stage> <Secret>; check the named Secret …`**: the hook could
  not create or read the named Secret, or an existing one has the wrong keys.
  It never prints values. A failed hook Job stays until the next attempt.
- **`setup stopped at <step> (<class>)`**: the step is, for example,
  `postgres/wait`, `schema`, `roles/<role>`, `fleet-source`, `openbao/login`
  or `objectstore/buckets`. The class is `invalid`, `denied`, `changed`,
  `deadline` or `unavailable`.
- **`retrying: … cause: …`**: setup waits up to five minutes for each
  unreachable provider and prints each failed attempt.
- **Pods stuck in `Init`**: the `wait-schema` init container waits until setup
  applies the schema. Its log prints `schema <n> is current` when done.
  `setup stopped at schema (changed)` means the database is newer than the
  image.

Fix the values and run the same `helm upgrade`. Never delete generated Secrets
or retained PVCs to clear an error: the data they protect would no longer
open.

## Production packaging contract

| Concern | Required behavior |
| --- | --- |
| Topology | One hub release in the management cluster; repeatable cluster enrollment without inbound node access; combined mode for evaluation |
| Identity and secrets | External OIDC or bundled Keycloak; separate browser/MCP/service clients. Generated Secrets created once by the `secrets` hook outside Helm release data, `existingSecret` overrides. No default passwords or upgrade-time regeneration |
| Dependencies | Independently selectable identity, key, database and object-store providers. No hidden service, operator or broker installation |
| Isolation | Separate runtime identities, bounded resources, Restricted control and analysis Pods; explicitly opted-in privileged collector namespace; no changes to workload namespaces |
| Optional features | No core interception by default; encrypted analysis scratch prerequisite; unavailable optional mechanisms explain their remedy without disabling context collection |
| Lifecycle | CRDs before dependent code; setup Job with the SQL administrator identity; forward-only schema; rollback keeps schema and Secrets |
| Configuration | Closed values schema, generated canonical CRDs, private registry and digest support, configuration changes through `helm upgrade` |
| Availability | Role-specific probes, replicas, leases, disruption policy, capacity and fair queues; a successful Helm install is distinct from collection readiness |
| Removal | Drain admission and recorders, preserve custody, audit and obligations, keep deletion workers until copies are verified gone; never delete CRDs, SQL or evidence in an uninstall hook |
| Air gap | Local chart archive and complete verified image bundle; no runtime internet lookup, update check, CDN, telemetry or registry fallback |
