# Asservat Helm chart

Helm is Asservat's officially supported installation method. The release layout is one hub and one cluster release per workload cluster; `combined` is for single-cluster evaluation. PostgreSQL, S3-compatible storage, KMS and Keycloak are operated separately. No dependency chart, external download hook or operator-managed credentials are bundled.

**Current version: configuration foundation with optional installer.** By default this development chart installs eight implemented CRDs, including CaptureProfile and a small release inventory ConfigMap. The optional `bootstrap.enabled` hook performs initial schema and activation; `bootstrap.continuation.enabled` adds runtime continuation as its fifth sequential command. The consolidated single-Pod runner passed the [external-services context trial](../../docs/installation/context-trial.md) with one hub and one separate workload cluster using preloaded images. Same-cluster qualification and registry distribution remain outside that result; [implementation status](../../docs/implementation-status.md) records the measured scope. Rendering the chart alone does not activate permissions, qualify an identity provider or collect evidence. `runtime.enabled: true` is rejected. The inventory ConfigMap records intent and is never an authority/readiness source.

For an installed pod-status capture and native download, use the [source-built context trial](../../docs/installation/context-trial.md). The commands below install the default configuration foundation only.

## Install the current foundation

Use a dedicated control namespace. The examples assume an administrator's explicit Kubernetes context. Tested versions and results are recorded in the repository's [Helm installation guide](../../docs/installation/helm.md); the current chart requires Kubernetes 1.35 or newer. A version constraint alone is not runtime qualification.

```sh
helm lint --strict ./charts/asservat
helm template asservat ./charts/asservat --namespace asservat-system --include-crds
kubectl --context MANAGEMENT_CONTEXT apply --server-side \
  --field-manager=asservat-crd-upgrade -f ./charts/asservat/crds
helm upgrade --install asservat ./charts/asservat \
  --kube-context MANAGEMENT_CONTEXT \
  --namespace asservat-system --create-namespace \
  --skip-crds --set mode=hub --wait --timeout 2m
```

In each separate workload cluster, run the same commands with its context and `--set mode=cluster`. For evaluation use `--set mode=combined`. The separate CRD apply establishes one field manager from the start so schema upgrades use the same owner. Helm can install missing CRDs directly if `--skip-crds` is omitted, but that requires an explicit ownership handoff before a later schema change. These modes currently record the intended topology; they do not enroll a cluster or start a runtime. Allow one Asservat installation per Kubernetes cluster. CRDs are cluster-scoped and shared; do not delete them on a namespace/release change.

For GitOps, use the same chart and checked-in nonsecret values. Give one administrator-managed application ownership of the cluster-scoped CRD bundle; other applications use their tool's equivalent of `--skip-crds`. Do not duplicate CRD ownership between tools. With bootstrap disabled, rendered resources do not contain Secrets, RBAC grants, admission policies or Pods. Enabling bootstrap adds an explicit trusted installer account/RBAC, immutable public input and fixed hook Pod; generated private state and native protections are product-owned. Administrative protection of the control namespace remains required before activating future runtime services.

| Value | Default | Meaning |
| --- | --- | --- |
| `mode` | `hub` | `hub`, `cluster` or `combined` release topology |
| `runtime.enabled` | `false` | Only `false` is supported by this development package |
| `bootstrap.enabled` | `false` | Run the fixed initial checkpoint; selected bundled-service support is scoped below |
| `bootstrap.continuation.enabled` | `false` | Add runtime continuation after retirement in the same fixed installer Pod |
| `bootstrap.name`, `targetNamespace`, `image` | `asservat`, `asservat-system`, empty | Stable original installation choices and verified image digest |
| `bootstrap.secrets.*` | empty | Provider-material input reference; external PostgreSQL also needs schema/retirement references |
| `bootstrap.registrySecret` | empty | Optional bootstrap-runner Docker auth Secret; not propagated to runtime workloads |
| `bootstrap.kubernetes`, `postgres`, `auditStore`, `keyService` | See values.yaml | Public endpoints, PEM roots and external provider choices |
| `bootstrap.fleet`, `providers`, `probeAudience` | See values.yaml | Explicit initial fleet scope/ceilings, fixed provider names and optional API audience |
| `bootstrap.continuation.public.permissionDelegations` | `[]` | Trusted initial AccessBinding writer envelopes and browser previewers; [configuration and scope](../../docs/installation/helm.md#delegate-permission-management) |

Unknown values are rejected to catch typos and avoid accepting ineffective security settings. Future runtime configuration will use existing Secret references. Never put passwords, tokens, client secrets, private keys or evidence in Helm values: Helm retains release state.

## Small-service candidate

The small profile is under implementation and is not yet an installation recipe.
`services.postgres.provider` selects `external` or `bundled`;
`services.objectStore.provider` selects `external` or `seaweedfs`;
`services.identity.provider` selects `external` or `keycloak`;
`services.keyService.provider` selects `external` or `openbao`. Each defaults to
`external` and can be selected independently. These are hub services; a
workload-cluster release must reuse the hub rather than install duplicates.

Bundled services require the trusted bootstrap namespace and `bootstrap.enabled`.
PostgreSQL additionally requires a built, verified PostgreSQL/pgBackRest image
pin. Keycloak requires its browser/Pod-reachable HTTPS hostname and an operator
TLS Secret. Its database may be the bundled PostgreSQL server or an explicitly
selected external database with password/CA Secret references. No password,
client secret or private key belongs in values.

A finite preparation hook retains generated provider credentials before any
provider initializes. Keycloak's selected database coordinates are part of its
retained state; changing them is not an implicit migration. Data/backup PVCs and
private state survive uninstall. Missing original state over retained data must
be recovered, not regenerated. If both PostgreSQL PVCs and every provider
workload are removed, surviving credential state alone cannot distinguish that
loss from an interrupted first preparation; that broader recovery case remains
unqualified. There is no precreated-PVC adoption option.

Component/render evidence, key-service packaging, provider setup and the full
login/capture/download/lifecycle qualification are tracked in the
[implementation ledger](../../docs/implementation-progress.md) and
[ADR-326](../../docs/decisions/326-individually-selectable-small-services.md).

The candidate's same-API regional path uses a second `mode: cluster` release in
the original hub bootstrap namespace. Set `cluster.bundledHub` to the original
bootstrap name and `cluster.bootstrapID` to the actual ID issued in `/fleet`;
`cluster.namespace` remains a distinct connector namespace. Leave manual offer,
bootstrap and evidence Secret references empty. The finite hook reuses the
original trusted bootstrap account, obtains the issued credential internally,
retains separate scoped keys and runs the normal connector install/catalog join.
Provider administration is serialized. This path has local checks; its full
installed workflow is still pending qualification.

## Named Go profile endpoint TLS

`cluster.profileEndpoints` accepts an optional `tls` object with `serverName`
and explicit public `rootsPEM`. The installer accepts only certificate PEM and
caps each input/canonical bundle at 8 KiB; all endpoint entries together retain
the existing 64 KiB JSON limit. The chart does not accept credentials, paths,
headers, URLs or an insecure TLS switch. Use a reusable template rather than
repeating large root bundles across per-application entries.

Upgrade connectors before collectors: older connector report decoders reject the
new optional `profileTLS` capability field. New connectors accept older nodes for
HTTP and refuse TLS starts unless the selected node reports that capability.
Passive preview alone does not establish node TLS support. TLS uses the existing
exact target network-namespace connection and original deadline, with no system
root or HTTP fallback. Installed TLS qualification is pending; this configuration
contract does not qualify or enable collection. See [ADR-299](../../docs/decisions/299-named-go-endpoint-tls.md).

## Optional bootstrap

Follow the [bootstrap operator flow](../../docs/installation/helm.md#optional-initial-bootstrap-checkpoint) for exact private file contracts, provider prerequisite recipe, one fresh Helm invocation and terminal-only `installer-resume`. Do not put secret bodies or dynamic UID/OID/digest bundles in values. With continuation enabled, one Pod runs produce, schema, prepare, retire and continue using separated credential mounts and one memory-only scratch volume. All five share the original 1,800-second Pod ceiling; phase and effect deadlines remain unchanged. The hook deletes itself only after success; failed/unknown hooks remain. Resume covers the final continuation as well as the earlier phases. Bootstrap-only completed replay can run without setup SQL/provider files; continuation still needs its documented input references. Private registry input remains a separate ongoing distribution dependency.

On upgrade, a live render-time lookup refuses a nonterminal, node-lost or deleting legacy `<bootstrap.name>-continuation` Pod. Completed legacy Pods are left alone; no Pod is adopted or removed by that check. Offline rendering cannot establish this live migration precondition.

## Regional cluster

With `mode=cluster` and `cluster.enabled`, a hook installs one regional connector from the hub's offer and an operator-created bootstrap Secret. See [add a regional cluster](../../docs/installation/helm.md#add-a-regional-cluster-modecluster). The bootstrap record is never a value.

## Node collector (test hosts only)

With `mode=cluster` or `combined` and `collector.enabled`, the chart creates the collector
namespace (the only namespace with the privileged Pod Security exception) and the `asservat node`
DaemonSet ([ADR-246](../../docs/decisions/246-node-collector-role.md)). Every collector Pod
mounts the host file `/etc/asservat-disposable-host` (hostPath type `File`), so it starts only on
disposable test hosts that carry it. It reports node capabilities and can execute
bounded, authorized manual header-only packet recordings when the matching Gadget-enabled product image,
regional listener and supported test-node profile are installed. Ongoing packet
and syscall sources remain unavailable. With `cluster.enabled` and an empty
`collector.connector`, the connector installer provisions the node listener and the chart reads its endpoint and root on the
next `helm upgrade`. See [node collector](../../docs/installation/helm.md#node-collector-test-hosts-only).

Optional `collector.live` passes the existing five node-processing ceilings to
`NodeDeployment.Live`: `subscriptions` (1–16), `memoryBytes` (1–16 MiB),
`eventsPerSecond` (1–100,000), `bytesPerSecond` (1–256 MiB/s) and
`processingNanosPerSecond` (1–100,000,000). All five are required together.
The default `null` keeps the previous rendered collector configuration unchanged
and live projections disabled. These processing reservations are separate from
the hub's protected `delivery.liveRead` viewer policy: neither starts a source
or grants access to one. No collector container limit is increased. Configured
ceilings require composed resource and disposable-host qualification; they are
not measured overhead or supported production defaults.

## Upgrade and uninstall

CRDs in `crds/` are installed on a first install but **are not upgraded or deleted by Helm**. Before changing versions, review the new CRD schemas and compatibility notes, preserve existing configuration/local start records, and back up the applicable state. From the unpacked, verified new chart:

```sh
kubectl --context MANAGEMENT_CONTEXT diff --server-side \
  --field-manager=asservat-crd-upgrade -f ./charts/asservat/crds
kubectl --context MANAGEMENT_CONTEXT apply --server-side \
  --field-manager=asservat-crd-upgrade -f ./charts/asservat/crds
helm upgrade asservat ./charts/asservat \
  --kube-context MANAGEMENT_CONTEXT --namespace asservat-system \
  --skip-crds --reset-values --set mode=hub --wait --timeout 2m
```

An exit code of 1 from `kubectl diff` means differences were found; inspect them. Resolve ownership conflicts deliberately; do not automatically force conflicts. Keep all chosen values in a file for nondefault installations and pass `-f` on upgrades. Changing topology is a migration, not an ordinary runtime upgrade. Future database migrations use a separate DDL identity and explicit expand/contract steps; chart rollback must never imply SQL/CRD rollback.

`helm uninstall asservat --kube-context MANAGEMENT_CONTEXT --namespace asservat-system` removes the foundation inventory and release state. CRDs and their custom resources remain. Do not delete the namespace or CRDs until required configuration, obligations and durable start/accounting records have been reconciled. Uninstalling a future runtime must drain/stop acquisition while preserving audit, expiry and verified deletion; it cannot abandon managed evidence.

## Package without publishing

```sh
helm package ./charts/asservat --destination ./dist
```

Install the resulting `.tgz` with Helm, including in disconnected environments. No image is needed with bootstrap disabled. Bootstrap requires the exact independently verified product image digest; no release image is published by this source change. The production release bundle will include verified images, CRDs, signatures, SBOMs and dependency notices alongside the OCI chart. No chart repository or OCI release has been published yet; do not substitute an unverified registry URL.


For independent manual collection approval, set
`bootstrap.continuation.public.approvals.stepUp` to the qualified provider's
`acrValues` and finite `maxAgeSeconds`. Set
`bootstrap.continuation.public.approvals.requireRecordingApproval: true` to
require that review for metadata packet/syscall recordings as well. These are
protected identity settings passed unchanged by the installer. Without step-up
settings, no independent approval can be decided; an absent `approvals` value
preserves the existing installation input.

Named endpoint Authorization (ADR-302, implementation preparation; installed
qualification pending) adds only public `credential.audiences` to
`cluster.profileEndpoints`. Each audience pins cluster ID, namespace UID,
workload kind (`Deployment`, `StatefulSet` or unowned `Pod`) and workload UID.
TLS is mandatory. The policy/key name is implicitly the endpoint name; clients
cannot choose another credential or file. Put the private map in the existing
`cluster.evidenceSecret` key `profile-authorization.json`:

```json
{"format":"asservat-profile-authorization/v1","entries":[{"name":"go-pprof","authorization":"QmVhcmVyIHN5bnRoZXRpYy1leGFtcGxl"}]}
```

`authorization` is base64-encoded bytes of the complete header value (the example
is synthetic), 1–4096 printable ASCII bytes. The map must contain exactly the
configured credentialed endpoint names, at most 64 entries/384 KiB total. Never
place values in Helm values, endpoint definitions or approval records. The CLI
uses `installer-cluster --profile-authorization <private-file>`. Existing immutable
bundle UID/version checks cover the file; changing material requires the same
guarded reinstall/restart as other private installation inputs. Upgrade connectors
before collectors, then use nodes reporting authorization support; old nodes
continue unauthenticated HTTP/TLS-only work and refuse credentialed work. There is
no automatic refresh, cleartext fallback, extra Secret or additional RBAC reader.
