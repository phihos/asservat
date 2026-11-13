# Install Asservat with Helm

Helm is the official installation and upgrade path. The [chart README](../../charts/asservat/README.md) contains the runnable commands and complete values table for the current package. The [operations contract](../operations.md) describes the eventual runtime profiles. TASK-11, REQ-UX-001 and REQ-ARC-001 cover installation ergonomics and role isolation.

For a source-built installation through enrollment, pod-status capture and native download, follow the [external-services context trial](context-trial.md). 

For a trial without separately operated PostgreSQL, S3, key-provider or identity services, use the [bundled-services context trial](small-profile.md). Its site values, source image builds and remaining qualification limits are explicit.

## Current scope

Version `0.1.0-dev.1` packages eight structural CRDs (AccessBinding,
PermissionSource, DebugPolicy, EvidenceRetentionPolicy, EvidenceBudgetPolicy,
EvidenceStoragePool, CapacityReservation, CaptureProfile) and renders every
Kubernetes object of an installation
([plan](../reviews/helm-native-install-plan.md)). Two Jobs do the work that
needs live state:

- `secrets` (pre-install and pre-upgrade hook) creates missing generated
  Secrets: installation IDs, SQL role passwords, audit MAC keys, the local
  artifact key, bundled SeaweedFS credentials and IAM, and the bundled
  provider state. It never rotates a value. Its Role allows only `create` on
  Secrets plus `get`/`patch` on the named ones.
- `setup` (an ordinary Job named after a hash of chart version, image and
  values) applies migrations, creates or updates runtime SQL roles and grants,
  seeds the trust and capacity rows and configures bundled OpenBao and
  SeaweedFS. Hub workloads wait in an init container until the schema is
  current.

There is no installer Pod, no admission-policy guard and no resume command.
Per-operation authority checks, evidence encryption, audit, SQL effect fences
and key confinement in the key service are unchanged.

The initial external identity provider is **Keycloak**. Reuse the [qualified
reference profile](../architecture/keycloak-profile.md); never put an
administrator password in values or infer authority from group display names.
[ADR-063](../decisions/063-small-deployment-alternatives.md) adds bundled
Keycloak, PostgreSQL, OpenBao and SeaweedFS as independent choices.

## Install

```sh
kubectl --context MANAGEMENT_CONTEXT apply --server-side \
  --field-manager=asservat-crd-upgrade -f ./charts/asservat/crds
helm upgrade --install asservat ./charts/asservat \
  --kube-context MANAGEMENT_CONTEXT \
  --namespace asservat-system --create-namespace \
  --skip-crds -f site-values.yaml
kubectl --context MANAGEMENT_CONTEXT -n asservat-system \
  wait --for=condition=Complete --timeout=15m \
  job -l app.kubernetes.io/component=setup
```

`site-values.yaml` contains `image` (repository and `sha256:` digest),
`origin`, `identity`, `exposure` and the provider selection under
`services`. With external providers supply their coordinates and public
roots under `services.<provider>.external`; external PostgreSQL also needs
`adminSecret`, an existing Secret with an administrator `credentials.json`
used only by `setup`. With an external object store, create the
`<name>-s3-<principal>` Secrets (`credentials.json`) yourself.

The [chart README](../../charts/asservat/README.md) lists every value and
generated Secret. To use an existing Secret instead of a generated one, set
`secrets.<key>.existingSecret`.

### Expose the console

`exposure.service.type` selects ClusterIP (default), NodePort or
LoadBalancer for `<name>-hub-api` (port 9445). `exposure.ingress` and
`exposure.httpRoute` render a generic Ingress or Gateway API HTTPRoute whose
host is the origin's host; the origin must then not carry a port. Use your
controller's own annotations; the chart adds none. In `exposure.tls.mode:
pod` hub-api terminates TLS with `exposure.tlsSecret` (for example issued by
cert-manager); in `proxy` mode the Ingress or Gateway terminates it
(ADR-327).

### Upgrade, rollback and uninstall

Apply CRDs first, then `helm upgrade` with the same values file. The hook
and `setup` run again; both are idempotent, so Argo CD's per-sync hooks are
safe. A rollback keeps the forward-only schema and the generated Secrets; an
older image refuses a newer schema. `helm uninstall` keeps PVCs, CRDs and
generated Secrets. Erasure is a separate explicit step.

### Failed Job

`kubectl -n asservat-system logs job/asservat-secrets` names the failing
stage and Secret, never a value. A failed hook Job stays until the next
attempt. `setup` retries with backoff; inspect its logs the same way.

## Delegate permission management

Set `identity.permissionDelegations` to let selected Kubernetes identities author AccessBindings
within a fixed envelope. The same entry names browser identities allowed to
preview those changes. The default `[]` delegates nothing. This packages the
existing [permission guard](../architecture/permission-acceptance.md) and
[access preview](../decisions/237-permission-impact-preview.md) configuration;
it adds no runtime component or automatic grant.

For example:

```yaml
identity:
  # Also configure issuer, clients and eligibility.
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

Changing the envelopes is an ordinary `helm upgrade`.

## Add a regional cluster (`mode=cluster`)

Remote regions install the connector templates of the same chart with
`mode=cluster` and the `region` values; the enrollment uses the bootstrap ID
issued through the browser `/fleet` view. A single-cluster installation uses
`mode=combined`, which runs the region in the hub cluster with in-cluster
addresses.

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
  name and PEM roots. Leave all three empty to read them from the ConfigMap `connector-nodes` in
  `region.namespace` through `lookup`; the first install then creates only the collector
  namespace and account, and the next `helm upgrade` starts the DaemonSet.
- `collector.ceilings` are the per-node ring, frozen, upload-rate and burst ceilings; the
  container memory limit is ring + frozen + 128 MiB.

The kubelet starts a collector Pod only on a host with `/etc/asservat-disposable-host`. Never
create that file on a workstation or shared cluster node; kind nodes share their host's kernel.
## Production packaging contract

| Concern | Required behavior when runtime roles are introduced |
| --- | --- |
| Topology | One hub release in the management cluster; repeatable cluster enrollment without inbound node access; combined mode for evaluation |
| Identity and secrets | External OIDC or local accounts; separate browser/MCP/service clients. Generated Secrets created once by the `secrets` hook outside Helm release data, `existingSecret` overrides. No default passwords or upgrade-time regeneration |
| Dependencies | Explicit small or external profile, independently selectable identity/key/database/store providers. Bundled PostgreSQL required; SeaweedFS and pgBackRest selected pending qualification. No hidden service/operator/broker installation |
| Isolation | Separate runtime identities, bounded resources, control/analysis Restricted pods; explicitly opted-in privileged collector namespace; no changes to workload namespaces |
| Optional features | No core interception by default; encrypted analysis scratch prerequisite; unavailable optional mechanisms explain their remedy without disabling qualified context collection |
| Lifecycle | CRD upgrade before dependent code; `setup` Job with the SQL administrator identity; forward-only schema; rollback keeps schema and Secrets |
| Configuration | Closed values schema, generated canonical CRDs, private registry/digest support, configuration changes through `helm upgrade` |
| Availability | Role-specific probes, replicas, leases/fencing, disruption policy, capacity and fair queues; successful Helm installation is distinct from collection readiness |
| Removal | Drain admission/recorders, preserve custody/audit/obligations, keep deletion workers until copies are verified gone; never delete CRDs/SQL/evidence automatically in an uninstall hook |
| Air gap | Local chart archive and complete verified image/tool bundle; no runtime internet lookup, update check, CDN, telemetry or registry fallback |
## Planned small profile

The accepted [dependency recommendations](../research/small-deployments.md) select local accounts/OAuth, an isolated static-key service, one PostgreSQL instance with pgBackRest and one SeaweedFS instance on persistent storage. These choices add no separately operated SSO/KMS/S3 service. They preserve TLS, encryption, role separation, native downloads, workload allocations and administrator retention caps. Small mode can manage multiple clusters; it is independent of the topology value. Each dependency can be replaced separately with a qualified external service.

The [small-profile candidate guide](small-profile.md) and [site values overlay](../../examples/helm/small-profile-values.yaml), merged after the finite context-trial profile, now select bundled PostgreSQL/pgBackRest, OpenBao, SeaweedFS and Keycloak. They document source image builds, storage/backup failure domains, single-instance downtime, retained state and the first operator workflow. Complete all four bundled services installed qualification and restore remain pending; the static-key alternative is unfinished. Optional offline analysis remains unavailable until encrypted scratch is qualified. REQ-DEP-001–005 and TASK-11 track the broader work.
## Verification

`make helm-check` (`scripts/check-helm.py`) validates the values schema, all
three modes, the `secrets` hook Job and its Role, the `setup` Job, generic
Ingress/HTTPRoute exposure, the example values, the collector DaemonSet,
invalid values and packaging. The Go test
`TestSecretsHookUsesRenderedPlanAndExactRole` runs the actual `asservat
secrets` code against the rendered plan through a fake API that enforces the
rendered Role. Installed qualification of the Helm-native flow is pending.

## Research and choices

Reviewed on 2026-10-10: [Helm's CRD lifecycle](https://helm.sh/docs/chart_best_practices/custom_resource_definitions/) explains why the chart keeps CRDs in `crds/` and requires explicit updates. [Chart structure and values schemas](https://helm.sh/docs/topics/charts/) support local archives and schema validation; that page warns that parts are not updated for Helm 4, so executable checks establish behavior for the installed version. [OCI distribution](https://helm.sh/docs/topics/registries/) is the selected publication format once release publication is authorized. No new templating framework, operator or chart-testing plugin is introduced.
