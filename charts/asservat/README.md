# Asservat Helm chart

Helm is Asservat's officially supported installation method. The release layout is one hub and one cluster release per workload cluster; `combined` is for single-cluster evaluation. PostgreSQL, S3-compatible storage, KMS and Keycloak are operated separately. No dependency chart, external download hook or operator-managed credentials are bundled.

**Current version: configuration foundation with optional initial bootstrap.** This development chart installs the four implemented CRDs and a small release inventory ConfigMap. The optional `bootstrap.enabled` hook packages the existing four-command initial installer; native qualification of this chart/private-registry composition is pending. It does not start the hub, console, MCP server or collectors. Installing this chart does not provide a working debugging platform, activate permission resources, qualify an identity provider or collect evidence. `runtime.enabled: true` is rejected. The inventory ConfigMap records intent and is never an authority/readiness source.

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
| `bootstrap.enabled` | `false` | Run the fixed initial checkpoint using explicit external services; no runtime enablement |
| `bootstrap.name`, `targetNamespace`, `image` | `asservat`, `asservat-system`, empty | Stable original installation choices and verified image digest |
| `bootstrap.secrets.*` | empty | Existing producer, schema and retirement private input references |
| `bootstrap.registrySecret` | empty | Optional explicit image-registry Docker auth Secret |
| `bootstrap.kubernetes`, `postgres`, `auditStore`, `keyService` | See values.yaml | Public endpoints, PEM roots and external provider choices |
| `bootstrap.fleet`, `providers`, `probeAudience` | See values.yaml | Explicit initial fleet scope/ceilings, fixed provider names and optional API audience |

Unknown values are rejected to catch typos and avoid accepting ineffective security settings. Future runtime configuration will use existing Secret references. Never put passwords, tokens, client secrets, private keys or evidence in Helm values: Helm retains release state.

## Optional bootstrap

Follow the [bootstrap operator flow](../../docs/installation/helm.md#optional-initial-bootstrap-checkpoint) for exact private file contracts, provider prerequisite recipe, one fresh Helm invocation and terminal-only `installer-resume`. Do not put secret bodies or dynamic UID/OID/digest bundles in values. The hook deletes itself only after success; failed/unknown hooks remain. Completed replay preserves original identities and can run without setup SQL/provider files. Private registry input remains a separate ongoing distribution dependency.

## Regional cluster

With `mode=cluster` and `cluster.enabled`, a hook installs one regional connector from the hub's offer and an operator-created bootstrap Secret. See [add a regional cluster](../../docs/installation/helm.md#add-a-regional-cluster-modecluster). The bootstrap record is never a value.

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
