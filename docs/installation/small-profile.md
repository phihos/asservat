# Try pod-status capture with bundled services

Build Asservat from source and install PostgreSQL/pgBackRest, OpenBao, SeaweedFS and Keycloak in your Kubernetes cluster. Enroll that same API as a workload region through a second Helm release. The cluster remains free of node collectors; this procedure targets pod-status capture.

**Qualified source-built context and restart trial.** A fresh installation with all four bundled services passed the five-command Helm installation, actual Keycloak login, regional enrollment, pod-status capture, native/range download, React inspection, expiry and managed deletion. The same workflow passed a PostgreSQL Pod restart using its retained volume, fresh console/MCP requests and retrieval of the earlier artifact without extending its bounds. Go and the owned-environment harness both exited0 at source `d6cc0ea9`; see the [implementation ledger](../implementation-progress.md) for source and cleanup evidence. This is a developer trial with no published Asservat/PostgreSQL release, production/HA qualification or supported physical restore procedure. Mixed-provider and broader lifecycle qualification remain separate work.

## Before you start

Use a fresh disposable installation on Kubernetes 1.35 or newer with Helm, kubectl, jq, OpenSSL, Docker, Python, the Go and Node/npm versions required by this checkout available (see `go.mod` and `web/package.json`). Build on the same OS/CPU architecture as your nodes. The chart supplies service workloads; you still supply persistent storage, DNS, routing, TLS serving certificates and image distribution. Source image builds also need a C compiler, make, flex, bison, curl, tar/xz and `file` for the pinned static libpcap build.

Choose an existing persistent StorageClass with enough space for the configured 64 GiB PostgreSQL data PVC, 64 GiB backup PVC, 8 GiB OpenBao PVC and 32 GiB object-store PVC. These quantities are configuration, not measured minimums or a storage assurance. Retain all PVCs and generated state Secrets together. Keeping backups on the same homelab storage is not independent disaster recovery.

The reference profile declares an 8 GiB evidence-store allowance and a 32 GiB logical root-WAL envelope, alongside finite row/object/key limits. Its one-second accounting horizon is a disposable-trial choice, not a backup/restore recommendation. Connector authority lasts 3,600 seconds with 4,000-second retained history. A single server or storage failure can interrupt this profile; no high availability is configured. Avoid unattended polling; sustained cleanup and complete finite metadata retirement remain separate qualification gaps.

Make these endpoints reachable from both your browser and cluster Pods:

| Endpoint | Direct TLS port |
| --- | --- |
| Keycloak, `login.lab.example.invalid` | 31451 |
| Browser/API, `asservat.lab.example.invalid` | 31450 |
| Federation, `federation.lab.example.invalid` | 31446 |
| Native owner, `owner.lab.example.invalid` | 31447 and 31449 |
| Artifact key service, `keys.lab.example.invalid` | 31448 |

Replace these example DNS names with your own. Route peer/native ports without terminating their mTLS at an HTTP ingress. The Kubernetes API address must also be reachable from the installer and runtime Pods, with a certificate covering that exact address. Do not use `insecure-skip-tls-verify`.

Every participating node needs access to the exact product and PostgreSQL image digests. Use anonymous or node-configured registry reads, or a genuinely preloaded-image setup accepted by your kubelet policy. `bootstrap.registrySecret` authenticates only the bootstrap runner: it does not propagate to runtime Pods. On current Kubernetes, a cached private image pulled by another Pod can still require pull credentials. Merely seeing the image in `crictl images` is insufficient.

## Build your images and chart

From the repository root, create a private working directory outside the checkout:

```bash
set -euo pipefail
SOURCE=$(pwd -P)
umask 077
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/asservat"
install -d -m 0700 "$STATE_DIR"
TRIAL=$(mktemp -d "$STATE_DIR/small-trial.XXXXXX")
install -d -m 0700 "$TRIAL/private" "$TRIAL/bin" "$TRIAL/package" "$TRIAL/public"
REV=$(git -C "$SOURCE" rev-parse --short=12 HEAD)
HUB_CONTEXT=REPLACE_CONTEXT
HUB_NAMESPACE=asservat-bootstrap
REGISTRY=registry.example.invalid
PRODUCT_REPO="$REGISTRY/asservat"
PG_REPO="$REGISTRY/asservat-postgres"
export ASSERVAT_BUILD_TMP="${XDG_CACHE_HOME:-$HOME/.cache}/asservat-build/tmp"
install -d -m 0700 "$ASSERVAT_BUILD_TMP"
export TMPDIR="$ASSERVAT_BUILD_TMP"
make -C "$SOURCE" image IMAGE="asservat:$REV"
make -C "$SOURCE" hub-binary HUB_BINARY="$TRIAL/bin/asservat"
install -d "$TRIAL/pg-build/packaging/postgres"
cp "$SOURCE/packaging/postgres/Dockerfile" "$SOURCE/packaging/postgres/entrypoint.sh" \
  "$SOURCE/packaging/postgres/postgresql.conf" "$SOURCE/packaging/postgres/pg_hba.conf" \
  "$TRIAL/pg-build/packaging/postgres/"
docker build -f "$TRIAL/pg-build/packaging/postgres/Dockerfile" \
  -t "asservat-postgres:$REV" "$TRIAL/pg-build"
helm package "$SOURCE/charts/asservat" --destination "$TRIAL/package"
ASSERVAT="$TRIAL/bin/asservat"
CHART_ARCHIVE="$TRIAL/package/asservat-0.1.0-dev.1.tgz"
```

The PostgreSQL Dockerfile builds the pinned pgBackRest source during image construction; the installed server downloads nothing at startup. Its server limit is 122 connections when Keycloak shares the bundled database, versus 117 without it. The initial installer client pool remains two connections. Do not lower these limits to make the deployment appear smaller.

The following commands publish into **your** registry when you run them. They are not an Asservat release:

```bash
docker login "$REGISTRY"
docker tag "asservat:$REV" "$PRODUCT_REPO:$REV"
docker push "$PRODUCT_REPO:$REV" | tee "$TRIAL/product-push.log"
PRODUCT_DIGEST=$(sed -n 's/.*digest: \(sha256:[a-f0-9]\{64\}\).*/\1/p' "$TRIAL/product-push.log" | tail -n 1)
PRODUCT_IMAGE="$PRODUCT_REPO@${PRODUCT_DIGEST:?missing registry manifest digest}"
docker tag "asservat-postgres:$REV" "$PG_REPO:$REV"
docker push "$PG_REPO:$REV" | tee "$TRIAL/postgres-push.log"
PG_DIGEST=$(sed -n 's/.*digest: \(sha256:[a-f0-9]\{64\}\).*/\1/p' "$TRIAL/postgres-push.log" | tail -n 1)
PG_IMAGE="$PG_REPO@${PG_DIGEST:?missing registry manifest digest}"
```

Use these registry manifest digests in values. A local Docker image ID can identify a config or OCI index; it is not interchangeable with a repository manifest reference. Configure node access to this registry before installation. For your own Kind cluster, `kind load docker-image "asservat:$REV" "asservat-postgres:$REV" --name YOUR_OWNED_CLUSTER` loads local images, but the chart still needs a digest reference that the node's CRI resolves to those exact images; importing a tag does not establish that reference or bypass credential verification. The registry path above avoids that extra alias step. Do not change kubelet verification policy just to make a cached private image start.

## Prepare site values, public trust and serving inputs

Copy the [site values example](../../examples/helm/small-profile-values.yaml) to your private working directory:

```bash
cp "$SOURCE/examples/helm/small-profile-values.yaml" "$TRIAL/site-values.yaml"
```

Replace all site placeholders. Set the built image digests to `$PRODUCT_IMAGE` and `$PG_IMAGE`; use your StorageClass and exact Kubernetes authenticated administrator username, obtainable with:

```bash
kubectl --context "$HUB_CONTEXT" auth whoami -o json
```

This Kubernetes administrator is separate from a browser user. Its existing protected configuration rights do not grant evidence access or make a Keycloak user an operator. The product adds its own original bootstrap-runner account independently.

Export your current Kubernetes public CA to `$TRIAL/public/api-ca.pem` using your cluster's trusted configuration. For a kubeconfig containing embedded CA data:

```bash
kubectl --context "$HUB_CONTEXT" config view --raw --minify \
  -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' |
  base64 --decode > "$TRIAL/public/api-ca.pem"
test -s "$TRIAL/public/api-ca.pem"
```

If that kubeconfig instead references a CA file, copy that public file. Do not copy a kubeconfig, client key or service-account token into Helm values.

Obtain four serving certificate/key pairs through your TLS process: Keycloak, public API, federation and key service. Each SAN must cover its exact configured hostname. Place them in `$TRIAL/private` as `keycloak.crt/keycloak.key`, `public.crt/public.key`, `federation.crt/federation.key` and `key-service.crt/key-service.key`. Place the public issuing roots in `$TRIAL/public/keycloak-ca.pem`, `federation-ca.pem` and `key-service-ca.pem`. Browser and cluster trust must accept these genuine roots; do not disable verification. With a private homelab CA, import its public root into your browser's trust store before login. The chart generates PostgreSQL, object-store and OpenBao TLS independently.

Create a fresh trusted Restricted bootstrap namespace. Existing namespace presence alone does not establish trust. Leave `asservat-system` creation to the installer:

```bash
kubectl --context "$HUB_CONTEXT" create namespace "$HUB_NAMESPACE"
kubectl --context "$HUB_CONTEXT" label namespace "$HUB_NAMESPACE" \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
kubectl --context "$HUB_CONTEXT" apply --server-side \
  --field-manager=asservat-crd-upgrade -f "$SOURCE/charts/asservat/crds"
kubectl --context "$HUB_CONTEXT" -n "$HUB_NAMESPACE" create secret tls operator-keycloak-tls \
  --cert="$TRIAL/private/keycloak.crt" --key="$TRIAL/private/keycloak.key"
kubectl --context "$HUB_CONTEXT" -n "$HUB_NAMESPACE" create secret generic operator-serving-material \
  --from-file=public-tls.crt="$TRIAL/private/public.crt" \
  --from-file=public-tls.key="$TRIAL/private/public.key" \
  --from-file=federation-tls.crt="$TRIAL/private/federation.crt" \
  --from-file=federation-tls.key="$TRIAL/private/federation.key" \
  --from-file=federation-ca.crt="$TRIAL/public/federation-ca.pem" \
  --from-file=key-service-tls.crt="$TRIAL/private/key-service.crt" \
  --from-file=key-service-tls.key="$TRIAL/private/key-service.key" \
  --from-file=key-service-ca.crt="$TRIAL/public/key-service-ca.pem"
```

This is the single phase-3 private serving-material Secret. Do not supply PostgreSQL administrators, an initial OpenBao token, an S3 administrator or an OIDC client secret. Selected preparation generates and retains them in their original protected state; the continuation reads the actual generated client secret. Do not copy synthetic fixture grants or fabricate installation IDs.

## Install the hub and check completion

The reference profile supplies finite capacity and retention declarations; the site overlay selects all four services. Keep the same original image pins, endpoints, namespace and release name on retries:

```bash
helm upgrade --install asservat "$CHART_ARCHIVE" \
  --kube-context "$HUB_CONTEXT" --namespace "$HUB_NAMESPACE" --skip-crds \
  -f "$SOURCE/examples/helm/context-trial-profile.yaml" -f "$TRIAL/site-values.yaml" \
  --set-string bootstrap.image="$PRODUCT_IMAGE" \
  --set-string services.postgres.bundled.image="$PG_IMAGE" \
  --set-file bootstrap.kubernetes.rootsPEM="$TRIAL/public/api-ca.pem" \
  --set-file bootstrap.continuation.public.promotion.providerRootsPEM="$TRIAL/public/keycloak-ca.pem" \
  --wait --timeout 20m
```

The finite preparation hook creates retained service material before their PVC-backed workloads start. PostgreSQL's backup container must become Ready after its first encrypted full backup. The subsequent original Pod runs `produce`, `schema`, `prepare`, `retire`, then `installer-continue`; automatic provider/S3 setup uses the original selected backend. There is no manual provider outbox loop for this all-bundled path. The continuation retains its original 300-second stage budget; a longer Helm timeout does not extend it or the original setup credentials.

Require Helm exit 0, its `asservat-bootstrap` hook success and successful hook removal, then inspect workloads:

```bash
helm status asservat --kube-context "$HUB_CONTEXT" --namespace "$HUB_NAMESPACE"
kubectl --context "$HUB_CONTEXT" -n "$HUB_NAMESPACE" get pods,pvc
kubectl --context "$HUB_CONTEXT" -n asservat-system get pods
```

The default bootstrap name is `asservat`, so the hook is `asservat-bootstrap`. A ready login page alone does not prove completed installation. On failure, inspect the retained original hook and its failing command. If the exact terminal hook blocks a corrected retry, use the existing bounded resume command, then repeat the same Helm command:

```bash
"$ASSERVAT" installer-resume --context "$HUB_CONTEXT" \
  --namespace "$HUB_NAMESPACE" --name asservat
```

Never force-delete a live hook, reset journals, rotate generated keys or delete retained PVCs to hide an error. Keep all generated state/PVCs together on upgrades. Uninstall is not reset or restore; it leaves retained data and obligations.

## Create the first human and initialize processing

Read the generated Keycloak administrator into private files without printing its password:

```bash
kubectl --context "$HUB_CONTEXT" -n "$HUB_NAMESPACE" get secret asservat-keycloak-state \
  -o jsonpath='{.data.bootstrap-admin-username}' | base64 --decode > "$TRIAL/private/keycloak-admin-username"
kubectl --context "$HUB_CONTEXT" -n "$HUB_NAMESPACE" get secret asservat-keycloak-state \
  -o jsonpath='{.data.bootstrap-admin-password}' | base64 --decode > "$TRIAL/private/keycloak-admin-password"
chmod 0600 "$TRIAL/private/keycloak-admin-username" "$TRIAL/private/keycloak-admin-password"
```

Open `https://login.YOUR_DOMAIN:31451/admin/`, use the generated credentials from those private files, then select realm `asservat`. Create your named human account and set a usable password. For the designated trial operator, explicitly assign membership in `asservat-users` and `asservat-processing-operators`. The processing group is created empty; enabling `processingOperators` alone assigns nobody.

Keep the generated `asservat_group_id` attributes unchanged. Their UUIDs, rather than display names, drive the imported token mapper and original protected settings. `asservat-users` grants eligibility and, under this reference fleet configuration, bootstrap issuance. It does not grant access to a workload. Processing membership grants the selected console client its explicit privacy-operator role; it is not a Kubernetes administrator.

Sign in through `https://asservat.YOUR_DOMAIN:31450`, open `/processing`, choose **Refresh processing rules**, then **Initialize processing** if uninitialized. This is a required explicit operator action before captures; do not substitute direct SQL or retained state edits.

## Enroll the same Kubernetes API as a workload region

Prepare this step before issuing the bootstrap, which expires in at most five minutes. The second release uses the **same original bootstrap namespace** and existing trusted `asservat-bootstrap-runner`, with its own connector namespace. It neither reinstalls the hub nor creates another user/provider service.

Open `/fleet`, enter the display name and region, keep delivery profile `regional-installer`, and choose **Issue bootstrap slot**. Copy the returned original `bootstrapID` and `clusterID`. Do not invent IDs or edit the deadline.

```bash
BOOTSTRAP_ID=REPLACE_WITH_ISSUED_BOOTSTRAP_ID
CLUSTER=REPLACE_WITH_ISSUED_CLUSTER_ID
jq -n --arg image "$PRODUCT_IMAGE" --arg id "$BOOTSTRAP_ID" \
  '{mode:"cluster",bootstrap:{enabled:false},collector:{enabled:false},cluster:{enabled:true,namespace:"asservat-connector",image:$image,bundledHub:"asservat",bootstrapID:$id}}' \
  > "$TRIAL/region-values.json"
helm upgrade --install asservat-region "$CHART_ARCHIVE" \
  --kube-context "$HUB_CONTEXT" --namespace "$HUB_NAMESPACE" --skip-crds \
  -f "$TRIAL/region-values.json" --wait --timeout 6m
kubectl --context "$HUB_CONTEXT" -n "$HUB_NAMESPACE" \
  logs job/asservat-region-cluster-installer -c installer > "$TRIAL/regional-installed.json"
jq -e --arg cluster "$CLUSTER" '.Join.clusterID == $cluster' "$TRIAL/regional-installed.json"
```

The hook reads version1 of that existing original bootstrap from the selected OpenBao channel, retains separate regional evidence/history keys before IAM changes, installs the connector, then joins its actual guarded sources to the hub. It does not issue a new bootstrap. Manual offer, bootstrap Secret and evidence Secret values must remain empty for this selected path. Regional private profile-authorization inputs are not supported by this chart branch.

## Grant one workload and capture pod status

Automatic enrollment does not create your workload policy or human AccessBinding. Use one existing synthetic Deployment. Obtain the generated users-group UUID as public policy input:

```bash
WORKLOAD_NS=REPLACE_WORKLOAD_NAMESPACE
DEPLOYMENT=REPLACE_DEPLOYMENT
OIDC_ISSUER=https://login.YOUR_DOMAIN:31451/realms/asservat # Exact configured issuer
TRIAL_GROUP_ID=$(kubectl --context "$HUB_CONTEXT" -n "$HUB_NAMESPACE" get secret asservat-keycloak-state \
  -o jsonpath='{.data.users-group-id}' | base64 --decode)
kubectl --context "$HUB_CONTEXT" label namespace "$WORKLOAD_NS" asservat-trial=true
```

Do not relabel a namespace protected by another accepted configuration. The initial `trial-apps` budget covers the hub ID, so create a separate regional policy and reserve one regional slot within the original 8 GiB pool. Run this once as the explicit Kubernetes administrator:

```bash
kubectl --context "$HUB_CONTEXT" -n asservat-system get evidencebudgetpolicy trial-apps -o json |
  jq --arg cluster "$CLUSTER" '{apiVersion,kind,metadata:{name:"trial-region",namespace:"asservat-system"},spec:(.spec | .scope.clusterID=$cluster | .namespaceEnvelope={maxWorkloadAccounts:1,maxStoredBytes:1610612736,maxObjects:3000})}' \
  > "$TRIAL/regional-policy.json"
kubectl --context "$HUB_CONTEXT" create -f "$TRIAL/regional-policy.json"
kubectl --context "$HUB_CONTEXT" -n asservat-system get evidencestoragepool trial -o json |
  jq '.spec.protectedAllocations += [{budgetPolicyRef:"trial-region",workloadSlots:1,protectedPerWorkload:{bytes:1073741824,objects:2000}}]' \
  > "$TRIAL/regional-pool-update.json"
# Review this resourceVersion update before replacement.
kubectl --context "$HUB_CONTEXT" replace -f "$TRIAL/regional-pool-update.json"
```

On conflict, re-read and review; do not force or append duplicate allocations on replay. Current source acceptance and SQL backing still determine admission. Bind the eligible group to the actual namespace and Deployment UIDs on this same API:

```bash
NAMESPACE_UID=$(kubectl --context "$HUB_CONTEXT" get namespace "$WORKLOAD_NS" -o jsonpath='{.metadata.uid}')
WORKLOAD_UID=$(kubectl --context "$HUB_CONTEXT" -n "$WORKLOAD_NS" get deployment "$DEPLOYMENT" -o jsonpath='{.metadata.uid}')
jq -n --arg cluster "$CLUSTER" --arg ns "$WORKLOAD_NS" --arg nsUID "$NAMESPACE_UID" \
  --arg workload "$DEPLOYMENT" --arg workloadUID "$WORKLOAD_UID" \
  --arg issuer "$OIDC_ISSUER" --arg group "$TRIAL_GROUP_ID" \
  '{apiVersion:"asservat.io/v1alpha1",kind:"AccessBinding",metadata:{name:"trial-region-maintainers",namespace:"asservat-system"},spec:{effect:"Allow",subjects:[{kind:"Group",issuer:$issuer,id:$group}],roles:["workload-maintainer"],scope:{clusterID:$cluster,namespaceRef:{name:$ns,uid:$nsUID},workloads:[{kind:"Deployment",name:$workload,uid:$workloadUID}]},reason:"Explicit context-only homelab trial"}}' \
  > "$TRIAL/regional-maintainers.json"
kubectl --context "$HUB_CONTEXT" create -f "$TRIAL/regional-maintainers.json"
```

The second Helm release already performs the join; do not run a second manual join. Neither automatic join nor browser eligibility supplies these workload permissions.

Once current sources and capacity are Ready, open `/captures/new`, choose the issued cluster and your Deployment, then **Find diagnostics**, **Review collection**, and **Collect pod status**. Inspect the resulting case and use the native download before its original expiry. The reference evidence default is 300 seconds plus a 300-second deletion budget. Verify subsequent reads refuse at expiry and managed deletion completes. Downloaded external copies remain yours to manage.

The all four bundled services context sequence has fresh installed qualification. That result does not qualify physical restore, every mixed-provider combination, larger evidence types or sustained operation.

The pinned Keycloak image is qualified for fresh login after the tested PostgreSQL restart using fixed idle connection validation. These raw Quarkus settings are outside Keycloak's first-class supported configuration. Requalify recovery before changing the Keycloak image; see the [decision and cost estimate](../decisions/326-individually-selectable-small-services.md#keycloak-idle-database-connections-after-postgresql-restart).


## Replace one bundled service

The four `services.*.provider` choices are independent and default to `external`. Make these choices before a fresh installation. Changing a completed installation's provider is not a supported migration or restore procedure. Keep the other selected services and their original inputs; do not copy the entire external-services example over this overlay.

| Replace | Select and supply | Existing input reference |
| --- | --- | --- |
| PostgreSQL | `services.postgres.provider: external`; set `bootstrap.postgres.host`, `port`, `database`, public `rootsPEM`, and the existing producer/schema/retirement Secret references. The initial client `maxConnections` remains 2; size the external server for the actual aggregate connection plan. If bundled Keycloak remains selected, configure its separate `services.identity.keycloak.database` host/name/user and password/CA Secret references as well. | [SQL credentials and Secret keys](helm.md#optional-initial-bootstrap-checkpoint), [external database prerequisites](context-trial.md#prepare-the-external-services-and-files), [Keycloak database selection](../../charts/asservat/README.md#small-service-candidate) |
| Object store | `services.objectStore.provider: external`; set `bootstrap.auditStore` endpoint/region/bucket/public roots and `bootstrap.continuation.public.federation.evidenceStore` to the actual qualified store. Supply the original initial storage credential through `bootstrap.secrets.producer` and the scoped continuation credentials described below. | [Initial private material](context-trial.md#prepare-the-external-services-and-files), [versioned storage and per-role recipe capabilities](context-trial.md#install-the-hub) |
| OpenBao | `services.keyService.provider: external`; set `bootstrap.keyService` endpoint/audit mount/key/public roots, continuation worker/owner auth mounts and their actual accessors, `ownerPKIMount`/`ownerIssuerRootsPEM`, and federation connector PKI mount/roots. Supply the finite initial issuer through the producer input. Existing external OpenBao mount, reviewer, PKI and KV prerequisites still apply. | [Initial provider prerequisites](context-trial.md#prepare-the-external-services-and-files), [continuation roles and inspection](helm.md#runtime-continuation-development) |
| Keycloak | `services.identity.provider: external`; supply the exact issuer, qualified client declarations, stable eligible/fleet/operator IDs, public identity-provider roots and private console client secret. No Keycloak Deployment, realm or users are created. | [External Keycloak configuration below](#use-your-existing-keycloak), [client/scopes and stable-ID mapper](../architecture/keycloak-profile.md), [site input example](../../examples/helm/context-trial-site.example.yaml) |

A mixed/external key-provider or store selection still uses the existing private `provider-material.json` in `bootstrap.secrets.producer`. It declares the format and original finite `storageUseUntil`; include `issuerToken` only for external OpenBao and `storage` only for an external object store. Omit the bundled provider's credential field rather than supplying a placeholder or another backend's credential. Keep separate PostgreSQL administrator inputs when PostgreSQL is external. The [external input procedure](context-trial.md#prepare-the-external-services-and-files) defines the credential bodies; no secret belongs in values.

With **bundled OpenBao and external S3**, keep `bootstrap.continuation.materialSecretName` pointing at your existing private material Secret. Add `configuration-audit-storage.json` for the phase-1 worker. Phase 3 uses `audit-storage.json` for the owner and, only when selected by the actual recipe, `federation-audit-storage.json`, `publisher-audit-storage.json`, `evidence-read.json`, `download-evidence-read.json`, `evidence-delete.json`, `cleanup-audit.json` and `cleanup-verify.json`. These are distinct narrowly scoped S3 credentials, using the closed `accessKeyID`/`secretAccessKey`/`sessionToken` JSON body. Retain the serving TLS files above and add `oidc-client-secret` if identity is external. The source must already contain the actual phase's inputs when read; the generated-prefix recipes are published in the existing outbox. After a named missing-input refusal, supply the exact source keys, observe terminal failure and follow the [existing resume procedure](helm.md#interrupted-or-failed-hook) with the same original values. The installer verifies retained progress; retry does not replace IDs or extend the original stage, credential or journal bounds, and expired bounds can still refuse. Do not substitute broad S3 administration or an OpenBao token. This path applies bundled OpenBao setup itself; it has no operator `installer-provider-apply` fallback.

With **bundled SeaweedFS and external OpenBao**, the continuation retains its generated original storage keys and private serving/identity inputs in its existing inbox. Answer each published worker/owner recipe with the existing local command:

```bash
"$ASSERVAT" installer-provider-apply --context "$HUB_CONTEXT" \
  --namespace "$HUB_NAMESPACE" --installation "$INSTALLATION"
```

Set `INSTALLATION` from the actual target namespace annotation as in the [outbox procedure](context-trial.md#install-the-hub). The OpenBao SDK uses your existing `BAO_ADDR`, `BAO_CACERT` and `BAO_TOKEN` environment for that actual external provider. Pass no credential or TLS file flags in this selected mixed path: the command consumes the retained original inbox. It never exports a bundled OpenBao administrator token. Mixed-provider installation qualification remains pending.

The automatic second-release regional procedure above selects the original bundled OpenBao and SeaweedFS sources. For an external key provider or store, use the [external regional enrollment procedure](context-trial.md#install-and-join-the-workload-cluster) and its actual issued credentials instead; the same-API helper does not discover an external provider.

### Use your existing Keycloak

Keep PostgreSQL, OpenBao and SeaweedFS bundled. In a final overlay after `small-profile-values.yaml`, select external identity and replace the following public placeholders with the existing realm's values:

```yaml
services:
  identity:
    provider: external
bootstrap:
  fleet:
    issuer: https://id.example.invalid/realms/company
    clients: [asservat-console, asservat-mcp]
    groups: [REPLACE_WITH_STABLE_FLEET_OPERATOR_GROUP_ID]
  continuation:
    public:
      issuer: https://id.example.invalid/realms/company
      clientID: asservat-console
      clients:
        - {id: asservat-console, kind: human}
        - {id: asservat-mcp, kind: human}
      eligibleGroups: [REPLACE_WITH_STABLE_USERS_GROUP_ID]
      processingOperators:
        - clientID: asservat-console
          issuer: https://id.example.invalid/realms/company
          kind: Group
          id: REPLACE_WITH_STABLE_PROCESSING_OPERATOR_GROUP_ID
```

Client IDs must match your actual qualified clients; omit the MCP declaration and fleet client if you are configuring only the console. Keep `bootstrap.continuation.public.origin` at your Asservat browser address. Set `promotion.browserAudience` to the configured API audience and use the external Keycloak's genuine public roots for the existing `--set-file bootstrap.continuation.public.promotion.providerRootsPEM=...` argument. Add the raw confidential console client secret as key `oidc-client-secret` to the **same** `operator-serving-material` Secret; there is no second phase-3 Secret. Append `--from-file=oidc-client-secret="$TRIAL/private/oidc-client-secret"` to the earlier `kubectl create secret generic operator-serving-material` command. Create/review that source before starting installation; this passes a file path, never the private value, in arguments.

Configure authorization code with S256 PKCE, exact redirect `<public.origin>/auth/callback`, the API audience, the built-in `basic` subject scope and the [required operation scopes and protected stable-ID mapper](context-trial.md#prepare-the-external-services-and-files). For sharing, include the profile's `evidence:share` scope. Public eligibility, fleet issuance and processing operation are separate explicit assignments. Create your human and memberships in your existing realm; skip this guide's generated Keycloak administrator retrieval and generated-group steps. Use the actual issuer and users-group ID in the regional `AccessBinding`. No generated Keycloak group UUID is added to external identity settings.
