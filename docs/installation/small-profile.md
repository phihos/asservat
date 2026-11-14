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

Replace these example DNS names with your own. Route peer/native ports without terminating their mTLS at an HTTP ingress.  Do not use `insecure-skip-tls-verify`.

Every participating node needs access to the exact product and PostgreSQL image digests. Use anonymous or node-configured registry reads, `image.pullSecrets`, or a genuinely preloaded-image setup accepted by your kubelet policy. On current Kubernetes, a cached private image pulled by another Pod can still require pull credentials. Merely seeing the image in `crictl images` is insufficient.

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
HUB_NAMESPACE=asservat-system
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

The PostgreSQL Dockerfile builds the pinned pgBackRest source during image construction; the installed server downloads nothing at startup. Its server limit is 122 connections when Keycloak shares the bundled database, versus 117 without it. Do not lower these limits to make the deployment appear smaller.

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

## Prepare site values and serving inputs

Copy the [site values example](../../examples/helm/small-profile-values.yaml) to your private working directory:

```bash
cp "$SOURCE/examples/helm/small-profile-values.yaml" "$TRIAL/site-values.yaml"
```

Replace all site placeholders. Set `image.repository`/`image.digest` to `$PRODUCT_IMAGE` and the PostgreSQL image to `$PG_IMAGE`, and use your StorageClass.

Obtain serving certificate/key pairs through your TLS process (for example cert-manager) for Keycloak, the console origin, federation and the key service. Each SAN must cover its exact configured hostname. Browser and cluster trust must accept these genuine roots; do not disable verification.

Create the release namespace with Pod Security `restricted`, apply the CRDs and create the TLS Secrets named in your values:

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
kubectl --context "$HUB_CONTEXT" -n "$HUB_NAMESPACE" create secret tls operator-console-tls \
  --cert="$TRIAL/private/public.crt" --key="$TRIAL/private/public.key"
```

Do not supply PostgreSQL administrators, an OpenBao token, an S3 administrator or an OIDC client secret. The `secrets` hook generates them once and keeps them in Secrets of the release namespace.

## Install the hub and check completion

The reference profile supplies finite capacity and retention declarations; the site overlay selects all four services:

```bash
helm upgrade --install asservat "$CHART_ARCHIVE" \
  --kube-context "$HUB_CONTEXT" --namespace "$HUB_NAMESPACE" --skip-crds \
  -f "$SOURCE/examples/helm/context-trial-profile.yaml" -f "$TRIAL/site-values.yaml" \
  --set-file identity.providerRootsPEM="$TRIAL/public/keycloak-ca.pem"
kubectl --context "$HUB_CONTEXT" -n "$HUB_NAMESPACE" \
  wait --for=condition=Complete --timeout=20m job -l app.kubernetes.io/component=setup
kubectl --context "$HUB_CONTEXT" -n "$HUB_NAMESPACE" get pods,pvc
```

The `secrets` hook creates the bundled provider state and the generated Secrets before the provider workloads start. The `setup` Job then waits for PostgreSQL, OpenBao and SeaweedFS, applies the schema and configures them; hub workloads start once the schema is current. A ready login page alone does not prove a completed installation; check that the setup Job completed.

On failure, read the logs of `job/asservat-secrets` or the `asservat-setup-*` Job; both name the failing stage. Fix the values and run the same `helm upgrade` again. Never delete generated Secrets or retained PVCs to hide an error. Uninstall keeps both.

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

Set `mode: combined` to run the workload region in the hub cluster with in-cluster addresses; no second release, bootstrap record or NodePort is needed. Separate workload clusters use their own `mode: cluster` release (see [add a regional cluster](helm.md#add-a-regional-cluster-modecluster)).

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

Each provider is selected independently. Set `services.<provider>.provider: external` and its `external` coordinates; keep the others bundled.

| Service | Values | Credentials |
| --- | --- | --- |
| PostgreSQL | `services.postgres.external`: `host`, `port`, `database`, public `rootsPEM`, `adminSecret` | `adminSecret` holds an administrator `credentials.json` used only by the setup Job. Runtime role passwords stay generated. With bundled Keycloak also set `services.identity.keycloak.database`. |
| Object store | `services.objectStore.external`: `endpoint`, `region`, `bucket`, `rootsPEM`; `federation.evidenceStore` | Create one `<name>-s3-<principal>` Secret (`credentials.json`) per principal listed in the [chart README](../../charts/asservat/README.md#generated-secrets). |
| OpenBao | `services.keyService.external`: `endpoint`, `rootsPEM` | Configure mounts, policies and Kubernetes auth as the setup recipe documents. |

### Use your existing Keycloak

Keep PostgreSQL, OpenBao and SeaweedFS bundled. In a final overlay after `small-profile-values.yaml`, select external identity:

```yaml
services:
  identity:
    provider: external
identity:
  issuer: https://id.example.invalid/realms/company
  clientID: asservat-console
  browserAudience: asservat-api
  clients:
    - {id: asservat-console, kind: human}
    - {id: asservat-mcp, kind: human}
  eligibleGroups: [REPLACE_WITH_STABLE_USERS_GROUP_ID]
  processingOperators:
    - clientID: asservat-console
      issuer: https://id.example.invalid/realms/company
      kind: Group
      id: REPLACE_WITH_STABLE_PROCESSING_OPERATOR_GROUP_ID
fleet:
  issuer: https://id.example.invalid/realms/company
  clients: [asservat-console, asservat-mcp]
  groups: [REPLACE_WITH_STABLE_FLEET_OPERATOR_GROUP_ID]
```

Pass the issuer's public roots with `--set-file identity.providerRootsPEM=...`. Configure authorization code with S256 PKCE, exact redirect `<origin>/auth/callback`, the API audience, the built-in `basic` subject scope and the [required operation scopes and protected stable-ID mapper](context-trial.md#prepare-the-external-services-and-files). Create your human and memberships in your existing realm.
