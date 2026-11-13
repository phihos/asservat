# Asservat Helm chart

Helm is Asservat's supported installation method. One hub release per
installation (`mode: hub`), one release per workload cluster
(`mode: cluster`), or one release for a single cluster (`mode: combined`).
Helm renders every Kubernetes object; Plain Kubernetes RBAC and Pod Security
`restricted` protect the release namespace.

PostgreSQL, S3-compatible storage, the key provider and the OpenID Connect
identity provider default to externally operated services. Each can be
replaced by a bundled workload (`services.*`); see the
[bundled-services guide](../../docs/installation/small-profile.md).

## Install

The chart requires Kubernetes 1.35 or newer.

```sh
kubectl --context MANAGEMENT_CONTEXT apply --server-side \
  --field-manager=asservat-crd-upgrade -f ./charts/asservat/crds
helm upgrade --install asservat ./charts/asservat \
  --kube-context MANAGEMENT_CONTEXT \
  --namespace asservat-system --create-namespace \
  --skip-crds -f site-values.yaml
```

`site-values.yaml` sets at least `image`, `origin`, `identity` and the
selected providers. An installation proceeds in three steps, all driven by
this one command:

1. The `secrets` hook Job (pre-install, pre-upgrade) creates every missing
   generated Secret and never changes an existing value.
2. The bundled providers start, if selected.
3. The `setup` Job applies the database schema, creates or updates the
   runtime SQL roles and configures bundled OpenBao and SeaweedFS. Hub
   workloads wait in an init container until the schema is current.

Configuration changes are applied with `helm upgrade` and the same values
file. There is no installer Pod and no resume command.

## Values

| Value | Default | Meaning |
| --- | --- | --- |
| `mode` | `hub` | `hub`, `cluster` or `combined` |
| `image.repository`, `image.digest` | empty | The product image, referenced only as `repository@sha256:…` |
| `image.pullPolicy`, `image.pullSecrets` | `IfNotPresent`, `[]` | Pull settings for every product Pod |
| `installation.name` | `asservat` | Prefix of every object name (DNS label, at most 30 characters) |
| `origin` | empty | Browser origin of the console and API, e.g. `https://asservat.example.org` |
| `identity.*` | see values.yaml | Issuer, console client, clients, eligibility, session limits, `approvals`, `processingOperators`, `permissionDelegations` |
| `processors`, `captureHistory` | omitted | Privacy inventory organizations; history view/cache ceilings |
| `exposure.service` | `ClusterIP` | Service type of hub-api (port 9445) |
| `exposure.tls.mode`, `exposure.tlsSecret` | `pod`, empty | ADR-327: TLS in hub-api with `tlsSecret`, or `proxy` behind an Ingress/Gateway |
| `exposure.ingress` | disabled | Generic Ingress: `className`, `annotations`, `tls`; the host is the origin host |
| `exposure.httpRoute` | disabled | Generic Gateway API HTTPRoute: `parentRefs`, `annotations`; the hostname is the origin host |
| `fleet` | see values.yaml | Fleet enrollment identity and bounds |
| `capacity`, `retention`, `federation` | omitted | Capacity root, baseline retention and federation listeners; former installer field names |
| `region` | see values.yaml | Connector settings for `cluster` and `combined` |
| `hub.<component>` | see values.yaml | `replicas`, `resources`, `nodeSelector`, `tolerations` of hub-api, hub-worker, federation, key-service, publisher |
| `secrets.<key>.existingSecret` | none | Use an existing Secret instead of generating it (see below) |
| `services.*` | external | Provider selection, external coordinates and bundled workloads |
| `collector.*` | disabled | Node collector (test hosts only) |

Unknown values are rejected. Never put passwords, tokens, client secrets,
private keys or evidence in values: Helm keeps release state.

An Ingress or HTTPRoute requires an origin without a port; the chart adds
no controller-specific annotations.

## Generated Secrets

The `secrets` hook creates these Secrets once in the release namespace.
They are never rotated, carry no Helm ownership and survive `helm uninstall`.
Its Role can only create Secrets and get or patch the named ones.

| Secret | Keys |
| --- | --- |
| `<name>-ids` | `installationID`, `clusterID`, `issuerEpoch`, `permissionRootID`, `browserRootID`, `sessionEpoch`, `roleSetupID`, `peerID` |
| `<name>-sql-<component>` | `sql-<purpose>.json` (`{"username","password"}`) per runtime SQL role of hub-api, hub-worker, federation, publisher, key-service |
| `<name>-audit-mac` | `inputVersion`, `inputKey`, `accountVersion`, `accountKey` |
| `<name>-artifact-key` | `keys.json`, the local artifact root keyset |
| `<name>-s3-<principal>` | `credentials.json`, bundled SeaweedFS only |
| `<name>-objectstore-iam` | `s3.json`, compiled from the s3 credentials |
| `<name>-postgres-state`, `-keycloak-state`, `-objectstore-state`, `-openbao-state` | bundled provider state |

Override one with `secrets.<key>.existingSecret`, for example
`secrets.sql-hub-api.existingSecret: my-hub-sql`; the Secret must hold the
same keys. With an external object store, create the `<name>-s3-<principal>`
Secrets yourself. A new key in a later chart version is added to an existing
Secret; present keys keep their values.

## Setup Job

`<name>-setup-<hash>` is an ordinary Job, not a hook. Its name changes with
the chart version, the image and the values, so every change runs it once.
It mounts `<name>-ids`, every `<name>-sql-*` Secret, the selected providers'
administrator credentials and the component ConfigMaps. Its Role allows
only `get` on ConfigMaps in the release namespace and on the namespace
itself. External PostgreSQL needs `services.postgres.external.adminSecret`,
a Secret with an administrator `credentials.json`.

## Node collector (test hosts only)

With `mode=cluster` or `combined` and `collector.enabled`, the chart creates
the collector namespace (the only namespace with the privileged Pod Security
exception) and the `asservat node` DaemonSet
([ADR-246](../../docs/decisions/246-node-collector-role.md)). Every collector
Pod mounts the host file `/etc/asservat-disposable-host`, so it starts only on
disposable test hosts. Optional `collector.live` passes the five node
processing ceilings; the default `null` disables live projections.

## Upgrade and uninstall

CRDs in `crds/` are not upgraded or deleted by Helm. Apply them first:

```sh
kubectl --context MANAGEMENT_CONTEXT apply --server-side \
  --field-manager=asservat-crd-upgrade -f ./charts/asservat/crds
helm upgrade asservat ./charts/asservat --kube-context MANAGEMENT_CONTEXT \
  --namespace asservat-system --skip-crds -f site-values.yaml
```

The schema only moves forward: a rollback keeps it, and an older image
refuses a newer schema. `helm uninstall` keeps PVCs, CRDs and the generated
Secrets. Erasing an installation is a separate, explicit step.

## Package without publishing

```sh
helm package ./charts/asservat --destination ./dist
```

No chart repository or OCI release has been published.
