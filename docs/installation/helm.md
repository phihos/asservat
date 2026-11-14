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
native download. External providers and separate workload clusters
(`mode: cluster`) are not qualified with this chart yet. The
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
key service (9447) and the hub-api native listener (9444). Only remote regions
need them reachable, through `hub.federation.service`,
`hub.key-service.service` and `hub.hub-api.nativeService` of type `NodePort`
or `LoadBalancer`. Route these as TCP; never terminate their mTLS at an HTTP
proxy. Their serving certificates come from `hub.<component>.tls.existingSecret`,
a cert-manager `issuerRef`, or a CA that the `secrets` hook generates once.

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

The objects below match the current setup Job. [ADR-330](../decisions/330-event-driven-system-design.md) removes the audit transit keys, owner/worker PKI, work-signing key and per-purpose roles; the target needs one installation CA, the connector PKI, artifact wrap/unwrap and browser-credential keys.

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

A `mode: cluster` release takes `region.clusterID` and `region.peerID` from a
bootstrap issued in the console (`/fleet`), the hub's `regional-offer.json` as
`region.offer`, and `region.bootstrapSecret`, a Secret with the bootstrap
record as `bootstrap.json`. The record is stored in OpenBao KV mount
`fleet-bootstrap` under `connector/<installationID>/<bootstrapID>`, is valid
for five minutes and works once. The connector seeds
`<name>-cluster-credential` from it and then rotates that credential itself.

The hub publishes its regional offer only in `mode: combined`, so remote
regions cannot be completed with this chart yet.

### Regional connector options

Options under `region.executor`:

- `alertmanager` ([ADR-231](../decisions/231-alert-detector.md)): the cluster's
  Alertmanager base URL for alert policies, for example
  `http://alertmanager-operated.monitoring.svc:9093`. The connector sends
  unauthenticated `GET /api/v2/alerts` requests and follows no redirect.
  ADR-330 replaces this pull with an in-cluster Alertmanager webhook receiver
  (connector Service plus a Helm-generated bearer Secret).
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

## Delegate permission management

[ADR-329](../decisions/329-accessbindings-in-application-namespaces.md) replaces this value: AccessBindings move to the application namespaces they grant, namespace RBAC decides who writes them, and a Helm-rendered ValidatingAdmissionPolicy requires `bind` on `accessroles.asservat.io` for each role (and on `automation` for `spec.automation`). Until that slice lands, the chart still reads the envelope below.

`identity.permissionDelegations` lets selected Kubernetes identities write
AccessBindings within a fixed envelope. The same entry names browser
identities allowed to preview those changes. The default `[]` delegates
nothing. See permission acceptance
and the [access preview](../decisions/237-permission-impact-preview.md).

```yaml
identity:
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

- `clusterID` and `namespace.uid` are the enrolled cluster ID and the current
  namespace UID. An empty `workloads` list covers the namespace; otherwise
  name each `Deployment` or `StatefulSet` with `kind`, `name` and `uid`.
  Recreating the namespace or workload needs a new envelope.
- `roles` may contain only `workload-maintainer`, `evidence-reader`,
  `evidence-owner` and `action-approver`. `issuers` limits which subject
  issuers a writer may bind.
- `writers` are Kubernetes usernames or groups (`kind: User` or `Group`); a
  service account is `system:serviceaccount:NAMESPACE:NAME`. Writers still
  need ordinary RBAC to write AccessBindings in the hub namespace.
- `previewers` are stable browser subject or group IDs. They gain no
  Kubernetes rights.

At most 64 envelopes are accepted, each with at least one writer and one
previewer. This delegates neither PermissionSource trust nor retention
administration.

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
