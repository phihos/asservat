# Try pod-status capture with external services

Install one hub, enroll a workload-cluster connector, and capture and download pod status through the browser. This source-built trial uses your PostgreSQL, S3-compatible storage, OpenBao and Keycloak. It installs no node collector; workloads remain under Pod Security `restricted`.

**Source-built developer trial.** The actual Helm/profile workflow passed with both separate hub/workload APIs and a shared Kubernetes API in owned reference environments: installation, enrollment, browser/MCP capture, native download, expiry refusal and verified evidence deletion. The images were preloaded; registry distribution remains outside those results. See [implementation progress](../implementation-progress.md) for exact source and results. There is no supported release or production/restore claim for this procedure.

Use the checked-in [trial profile](../../examples/helm/context-trial-profile.yaml) together with your edited [site example](../../examples/helm/context-trial-site.example.yaml). The profile supplies finite budgets; the site file supplies public endpoints, identities and the image digest. Keep private inputs outside the checkout and Helm release history.

## Trial bounds

The profile admits two workload accounts with eight capture records each. Default evidence access is 300 seconds, with a further 300-second deletion budget; case and audit defaults are one hour. Complete inspection and download before expiry. Native copies on your workstation remain yours to manage.

The verified journey explicitly requested 80 seconds and checked its original expiry. It does not measure every duration or maximum supported by the configuration.

The connector admits work for 3,600 seconds and retains its history for 4,000 seconds. Operation/source transition counts are finite. Sustained operation and automatic normal/resolution history recycling are not qualified by this trial; avoid unattended polling.

The 8 GiB evidence backend must actually meet the declared `qualifiedReservedBackend` assurance. It is separate from PostgreSQL data, WAL and backup capacity. The profile's 32 GiB root WAL envelope is a maximum prepaid obligation, not an immediate allocation or traffic estimate; connector/source history has additional backing. The one-second residual accounting horizon (`H=1`, one backup and WAL copy) is a disposable-trial choice, not a supported backup or restore configuration. The configured row/WAL footprints remain declarations rather than universal measurements.

## Prepare the external services and files

Use Kubernetes 1.35 or newer, Helm, kubectl, jq and the OpenBao `bao` CLI. Building from source also needs the repository's Go/Node toolchain, Python, Docker and the C/static-build tools used by `make hub-binary`. The CLI and image built below target the build host's architecture; use matching cluster nodes. The product does not install these tools or external services.

Prepare these prerequisites before starting the 1,800-second installer runner:

1. A fresh empty PostgreSQL database with verified TLS and the separate setup-administrator, DDL and retirement-administrator credentials. Runtime role provisioning uses the real compiled grant plan. The installed connection plan still needs 114 ordinary slots, 117 total with three superuser-reserved slots and no other reservation; this small record profile does not reduce that floor. Account separately for your other clients.
2. Separate versioned audit and evidence buckets, current CA roots and provider-qualified object/version/multipart behavior. Have an S3 administrator available to issue the exact private capabilities requested during continuation. Do not use a bucket-wide root credential as a runtime capability.
3. OpenBao with its audit Transit mount/key, initial finite issuer/roles/policies, `hub-worker-k8s` and `hub-owner-k8s` Kubernetes auth mounts configured for this hub, real mount accessors, `owner-pki`, `connector-pki`, `worker-pki`, `public-transit`, and KV-v2 mount `fleet-bootstrap`. Mounts, CA roots and Kubernetes reviewer setup remain operator prerequisites; the continuation creates the named per-installation keys/roles and validates the resulting recipe.
4. The Keycloak reference configuration: a confidential `asservat-console` client, authorization-code + PKCE S256, exact redirect `<public.origin>/auth/callback`, access-token audience `asservat-api`, builtin `basic` subject scope, and default client scopes `evidence:read`, `evidence:capture`, `evidence:download`. Configure the protected stable-ID `asservat_groups` mapper as described in the [Keycloak profile](../architecture/keycloak-profile.md). Do not enable implicit/password/service-account grants for the human client. Obtain its private client secret.
5. DNS and L4 routing to the hub's NodePorts: federation 31446, owner 31447, owner-operation 31449, key service 31448, browser/API 31450. Preserve their actual TLS connections; do not terminate peer mTLS at an HTTP ingress. The API endpoint must also be reachable by the installer/owner/worker Pods.
6. Three serving pairs: browser/API, federation and key service. Federation/key-service inputs each require certificate-chain PEM, matching private-key PEM, and explicit current CA roots PEM. Federation SAN must match `federation.serverName`; key-service SAN must match the hostname of `keyServiceEndpoint`. Use your certificate process. The product neither creates these CAs nor regenerates the supplied certificates.
7. An existing target Deployment and namespace in the workload cluster. Use synthetic workload data for the trial. Set `HUB_CONTEXT` and `WORKLOAD_CONTEXT` to explicit kubeconfig contexts. Separate clusters and the same context for both have passed the named context journey. With one context, keep the hub, connector and application in their distinct namespaces; the regional CLI enrolls the workload role after the hub Helm release. This does not qualify a combined single-release installer.

Set `bootstrap.administrators` to your **real Kubernetes authenticated** User/Group identity. For example, inspect `kubectl --context "$HUB_CONTEXT" auth whoami -o json`; use the returned username, not the kubeconfig context label. The runner is independently derived and added. An explicit list supports at most 31 actors plus the runner. This lets the original operator perform post-install management through the real kubeconfig; no impersonation is required. It grants no browser/evidence role.

Replace every `example.invalid` and `REPLACE_WITH_…` site placeholder. `public.eligibleGroups`, `fleet.groups` and `processingOperators` are separate permissions; choose stable IDs deliberately. `processors: []` in the reference file is an explicit declaration that there are no processor organizations. If that is false for your services, replace it with truthful supported declarations, or remove the key to report them as undeclared.

## Build matching artifacts and prepare a private directory

Start in the source checkout you intend to install. Create a separate working directory, then use it in both terminals throughout the procedure:

```sh
SOURCE=$(pwd -P)
umask 077
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/asservat"
install -d -m 0700 "$STATE_DIR"
TRIAL=$(mktemp -d "$STATE_DIR/context-trial.XXXXXX")
install -d -m 0700 "$TRIAL/private" "$TRIAL/bin" "$TRIAL/package"
cp "$SOURCE/examples/helm/context-trial-site.example.yaml" "$TRIAL/site-values.yaml"
cd "$TRIAL"
make -C "$SOURCE" image IMAGE=asservat-context-trial:local
make -C "$SOURCE" hub-binary HUB_BINARY="$TRIAL/bin/asservat"
helm package "$SOURCE/charts/asservat" --destination "$TRIAL/package"
ASSERVAT="$TRIAL/bin/asservat"
CHART_ARCHIVE="$TRIAL/package/asservat-0.1.0-dev.1.tgz"
printf 'Trial directory for both terminals: %s\n' "$TRIAL"
```

Use a build filesystem with room; `ASSERVAT_BUILD_TMP` defaults to `$HOME/.cache/asservat-build/tmp`. `make image` builds the product executable and compiled React assets locally. It does not push an image. Distribute that image through your existing registry process and set `bootstrap.image` to its actual `repository@sha256:…` registry manifest digest. The printed local image ID is not that digest. `bootstrap.registrySecret` authenticates only the bootstrap runner; it is not propagated to runtime, regional or download Pods. For this trial, every participating node must be able to pull the exact digest through anonymous or node-configured registry access, or have that image preloaded. If the bootstrap runner also needs a pull Secret, create it in `asservat-bootstrap` before Helm and set `bootstrap.registrySecret` to its name.

Place the following private files in `$TRIAL/private`, mode 0600. All paths below are relative to `$TRIAL`; neither credentials nor evidence belong in the checkout, Helm values or command arguments.


| File used below | Exact body |
| --- | --- |
| `postgres-administrator.json`, `postgres-ddl.json`, `postgres-retirement.json` | Closed JSON `{"username":"…","password":"…"}` for the selected SQL identity |
| `initial-storage.json` and each later storage-capability file | Closed JSON `{"accessKeyID":"…","secretAccessKey":"…","sessionToken":""}`; nonempty session token only if issued by your provider |
| `provider-material.json` | The initial material object below |
| `oidc-client-secret` | Raw private client-secret bytes |
| `public.crt`, `public.key` | Browser/API certificate chain and matching key |
| `federation.crt`, `federation.key`, `federation-ca.pem` | Federation serving bundle |
| `key-service.crt`, `key-service.key`, `key-service-ca.pem` | Key-service serving bundle |

The initial material is a closed static object, not a dynamically minted bootstrap record:

```json
{"format":"asservat-initial-bootstrap-material/v1","issuerToken":"FINITE_INITIAL_ISSUER","storage":{"accessKeyID":"ISSUED_ID","secretAccessKey":"ISSUED_SECRET","sessionToken":""},"storageUseUntil":"ACTUAL_ORIGINAL_UTC_DEADLINE"}
```

Use the genuine issued issuer and storage-use bound; do not invent installation IDs or extend provider credentials by choosing a later timestamp. This object is bounded to 8 KiB and the issuer token to 1,024 bytes.

Generate the exact initial nonsecret OpenBao recipe:

```sh
"$ASSERVAT" installer-provider-recipe > provider-prerequisites.json
```

Review the emitted Transit mount/key/type, three policy strings, two token-role objects and finite issuer-token request. Apply them using your existing OpenBao administrative tooling and obtain only that limited issuer for `provider-material.json`. The command makes no request; it does not configure mounts or issue the token. Preserve existing key identity; never blindly overwrite keys, roles or policy. Flags must stay aligned if you change the profile's default names.

## Install the hub

Set `WORKLOAD_NS`, `DEPLOYMENT`, `TRIAL_GROUP_ID` and `OIDC_ISSUER` to your actual target and stable identity values. The issuer/group must match the site file. In terminal B, set `SOURCE`, `TRIAL`, `ASSERVAT` and the same context variables, and `cd "$TRIAL"`. Keep OpenBao administrative access in the process environment (`BAO_ADDR`, `BAO_CACERT`, `BAO_TOKEN`), not in values or logs.

```sh
kubectl --context "$HUB_CONTEXT" create namespace asservat-bootstrap
kubectl --context "$HUB_CONTEXT" label namespace asservat-bootstrap \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

Use a trusted fresh bootstrap namespace, distinct from `asservat-system`. If it already exists, establish its trust separately; `AlreadyExists` is not historical-cleanliness proof. Leave product target-namespace creation to the installer.

Apply the shipped CRDs once per distinct cluster, retaining this field manager for future upgrades:

```sh
kubectl --context "$HUB_CONTEXT" apply --server-side \
  --field-manager=asservat-crd-upgrade -f "$SOURCE/charts/asservat/crds"
if [ "$WORKLOAD_CONTEXT" != "$HUB_CONTEXT" ]; then
  kubectl --context "$WORKLOAD_CONTEXT" apply --server-side \
    --field-manager=asservat-crd-upgrade -f "$SOURCE/charts/asservat/crds"
fi
```

Create only the three upstream setup-input Secrets; these are not final product credentials or TLS Secrets:

```sh
kubectl --context "$HUB_CONTEXT" -n asservat-bootstrap create secret generic operator-producer \
  --from-file=postgres-administrator.json=private/postgres-administrator.json \
  --from-file=provider-material.json=private/provider-material.json
kubectl --context "$HUB_CONTEXT" -n asservat-bootstrap create secret generic operator-schema \
  --from-file=postgres-ddl.json=private/postgres-ddl.json
kubectl --context "$HUB_CONTEXT" -n asservat-bootstrap create secret generic operator-retirement \
  --from-file=postgres-administrator.json=private/postgres-retirement.json
```

Run Helm in terminal A; it waits while the operator services two provider recipe phases from terminal B:

```sh
helm upgrade --install asservat "$CHART_ARCHIVE" \
  --kube-context "$HUB_CONTEXT" --namespace asservat-bootstrap --skip-crds \
  -f "$SOURCE/examples/helm/context-trial-profile.yaml" -f "$TRIAL/site-values.yaml" \
  --set-file bootstrap.kubernetes.rootsPEM=api-ca.pem \
  --set-file bootstrap.postgres.rootsPEM=postgres-ca.pem \
  --set-file bootstrap.auditStore.rootsPEM=s3-ca.pem \
  --set-file bootstrap.keyService.rootsPEM=bao-ca.pem \
  --set-file bootstrap.continuation.ownerIssuerRootsPEM=owner-ca.pem \
  --set-file bootstrap.continuation.public.federation.connectorIssuerRootsPEM=connector-ca.pem \
  --set-file bootstrap.continuation.public.federation.evidenceStore.rootsPEM=s3-ca.pem \
  --set-file bootstrap.continuation.public.promotion.providerRootsPEM=idp-ca.pem \
  --wait --timeout 30m
```

Retain this command, public files, CA files and image pin for exact replay. The hook Pod has an original 1,800-second ceiling independent of Helm's wait. The CA filenames above are public trust files in `$TRIAL`; use the actual roots for each endpoint.

In terminal B, observe the original runner:

```sh
kubectl --context "$HUB_CONTEXT" -n asservat-bootstrap get pod asservat-bootstrap -w
```

Once `asservat-system` exists, press Ctrl+C to stop the watch; this does not stop the installer Pod. Continue in terminal B:

```sh
INSTALLATION=$(kubectl --context "$HUB_CONTEXT" get namespace asservat-system -o json |
  jq -er '.metadata.annotations["asservat.io/installation-id"]')
OUTBOX="asservat-$(printf %s "$INSTALLATION" | tr -d '-')-installer-outbox"
kubectl --context "$HUB_CONTEXT" -n asservat-bootstrap get configmap "$OUTBOX" -o json |
  jq -er '.data["outbox.json"] | fromjson' > current-recipe.json
```

Inspect `current-recipe.json` for `phase: 1`, `purpose: worker-provider`. Re-read the ConfigMap until that recipe exists. Do not guess a pending recipe or create an inbox manually. Read `.recipe.auditStorage`, have the provider administrator issue its exact scoped audit capability, and save its private credential as `private/worker-audit.json`. Then submit it with the local helper:

```sh
"$ASSERVAT" installer-provider-apply --context "$HUB_CONTEXT" \
  --namespace asservat-bootstrap --installation "$INSTALLATION" \
  --audit-credential private/worker-audit.json
```

The helper applies missing recipe keys/roles/ACL configuration, obtains a ten-minute read-only inspection token, and writes the private inbox through the actual administrative identity. The continuation validates and consumes it. It does not issue S3 IAM credentials.

Repeat the outbox read command after phase 1, wait for `phase: 3`, `purpose: owner-provider`, and provision the separate capabilities named by `.recipe.auditStorage`, `.recipe.federationAuditStorage`, `.recipe.publisher.auditStorage`, `.recipe.publisher.evidenceReadStorage`, `.recipe.downloadEvidenceReadStorage`, `.recipe.evidenceDeleteStorage` and
`.recipe.operationCleanupStorage.cleanup`/`.verify`. Use their exact emitted prefixes/actions; no generated UUID, SQL OID or digest is an operator input.
The cleanup principal may create only immutable deletion certificates and delete
the selected audit objects; the separate verifier cannot write or delete. Save
their distinct credentials as `private/cleanup-audit.json` and
`private/cleanup-verify.json`. Neither receives evidence-bucket or storage-admin
rights. Then run:

```sh
"$ASSERVAT" installer-provider-apply --context "$HUB_CONTEXT" \
  --namespace asservat-bootstrap --installation "$INSTALLATION" \
  --audit-credential private/owner-audit.json \
  --federation-audit-credential private/federation-audit.json \
  --evidence-read-credential private/publisher-evidence-read.json \
  --publisher-audit-credential private/publisher-audit.json \
  --download-evidence-credential private/download-evidence-read.json \
  --evidence-delete-credential private/evidence-delete.json \
  --cleanup-audit-credential private/cleanup-audit.json \
  --cleanup-verify-credential private/cleanup-verify.json \
  --oidc-client-secret private/oidc-client-secret \
  --public-tls-certificate private/public.crt --public-tls-key private/public.key \
  --federation-tls-certificate private/federation.crt \
  --federation-tls-key private/federation.key --federation-tls-ca private/federation-ca.pem \
  --key-service-tls-certificate private/key-service.crt \
  --key-service-tls-key private/key-service.key --key-service-tls-ca private/key-service-ca.pem
```

Only pass private optional sections when present in this actual recipe. The context profile selects them all. The serving bundles must match the outbox's two `servingTLS` hostnames. The product creates its fixed final Secrets, or reopens identical content after an uncertain create; do not seed or replace those final Secrets yourself.

Require Helm exit 0 and the hook's success-policy removal, then check the runtime workloads in `asservat-system` with `kubectl --context "$HUB_CONTEXT" -n asservat-system get pods`. A ready browser page alone does not establish completion. Once full original closure is independently verified, retire the upstream setup credentials and remove their operator-owned Secrets/files according to your process. Do not remove the producer input while continuation still needs it. Keep optional registry pull input if nodes still need it.

## Install and join the workload cluster

Prepare the workload namespace before the connector installs its label guard:

```sh
kubectl --context "$WORKLOAD_CONTEXT" label namespace "$WORKLOAD_NS" asservat-trial=true
```

Do not relabel a namespace already guarded by a different accepted configuration. Obtain the actual offer from the target namespace:

```sh
OFFER="asservat-$(printf %s "$INSTALLATION" | tr -d '-')-regional-offer"
kubectl --context "$HUB_CONTEXT" -n asservat-system get configmap "$OFFER" -o json |
  jq -er '.data["regional-offer.json"]' > regional-offer.json
```

Sign in at `public.origin` as the configured eligible fleet operator, open `/fleet`, and issue one bootstrap with your display name and region under delivery profile `regional-installer`. Preserve the returned `bootstrapID`, `clusterID`, original deadline and delivery profile. The response contains no secret. Use the issued bootstrap ID below, never a chosen UUID. It expires in at most five minutes; have your regional namespace, real provider administration and storage policy process ready before issuance.

Use [OpenBao `kv get`](https://openbao.org/docs/commands/kv/get/) to read **version 1** of the exact existing KV record through authorized access. `DecodeBootstrapRecord` consumes the inner binding-and-secret object, not the entire KV HTTP envelope:

```sh
# BOOTSTRAP is the exact bootstrapID returned by /fleet.
bao kv get -mount=fleet-bootstrap -version=1 -format=json \
  "connector/$INSTALLATION/$BOOTSTRAP" |
  jq -e '.data | select(.metadata.version == 1 and .metadata.destroyed == false and .metadata.deletion_time == "") | .data' \
  > private/bootstrap.json
"$ASSERVAT" installer-provider-recipe --history-offer regional-offer.json \
  --history-bootstrap private/bootstrap.json > regional-provider-recipe.json
```

Keep the resulting private `{binding,secret}` record unchanged. The installer checks its exact format, original identity/deadline and current SQL claim. An expired bootstrap cannot be repaired by editing the file.

Have the provider administrator issue the write-only regional evidence capability and the **separate** history read/write/inventory/delete capability. The recipe supplies `regionalHistory.seaweedIdentityActions` and `regionalHistory.s3BucketPolicy`; merge the exact policy with existing protection. These are proposals, not created IAM identities. The history identity must not read/delete evidence and the evidence writer must not gain history cleanup or key-unwrapping rights. Save only the resulting closed credential objects into the two private files:

```sh
"$ASSERVAT" installer-cluster --context "$WORKLOAD_CONTEXT" \
  --namespace asservat-connector --offer regional-offer.json \
  --bootstrap private/bootstrap.json \
  --evidence-credential private/evidence-writer.json \
  --history-credential private/history-storage.json > regional-installed.json
jq -e '.Join' regional-installed.json > regional-join.json
CLUSTER=$(jq -er '.clusterID' regional-join.json)
```

The CLI result uses uppercase `.Join`; its inner record uses `clusterID`. Leave collector and profile-endpoint flags absent.

Before joining, create the regional policy using the accepted initial desired policy as a public template, pinning the actual regional ID. The initial `trial-apps` policy is pinned to the **hub**, so it cannot cover the region. The profile reserves physical space in advance; add one 1 GiB/2,000-object regional slot without raising the declared 8 GiB backend:

```sh
kubectl --context "$HUB_CONTEXT" -n asservat-system get evidencebudgetpolicy trial-apps -o json |
  jq --arg cluster "$CLUSTER" '{apiVersion,kind,metadata:{name:"trial-region",namespace:"asservat-system"},spec:(.spec | .scope.clusterID=$cluster | .namespaceEnvelope={maxWorkloadAccounts:1,maxStoredBytes:1610612736,maxObjects:3000})}' \
  > regional-policy.json
kubectl --context "$HUB_CONTEXT" create -f regional-policy.json
kubectl --context "$HUB_CONTEXT" -n asservat-system get evidencestoragepool trial -o json |
  jq '.spec.protectedAllocations += [{budgetPolicyRef:"trial-region",workloadSlots:1,protectedPerWorkload:{bytes:1073741824,objects:2000}}]' \
  > regional-pool-update.json
kubectl --context "$HUB_CONTEXT" replace -f regional-pool-update.json
```

This is a one-time read/resourceVersion update. Inspect it before replacement; on conflict re-read and review, not force. Do not append duplicate allocations on replay. Actual source acceptance and finite SQL root backing still decide whether this policy can admit work.

Bind the real eligible group to this exact workload. Use actual namespace and Deployment UIDs from the workload API:

```sh
NAMESPACE_UID=$(kubectl --context "$WORKLOAD_CONTEXT" get namespace "$WORKLOAD_NS" -o jsonpath='{.metadata.uid}')
WORKLOAD_UID=$(kubectl --context "$WORKLOAD_CONTEXT" -n "$WORKLOAD_NS" get deployment "$DEPLOYMENT" -o jsonpath='{.metadata.uid}')
jq -n --arg cluster "$CLUSTER" --arg ns "$WORKLOAD_NS" --arg nsUID "$NAMESPACE_UID" \
  --arg workload "$DEPLOYMENT" --arg workloadUID "$WORKLOAD_UID" \
  --arg issuer "$OIDC_ISSUER" --arg group "$TRIAL_GROUP_ID" \
  '{apiVersion:"asservat.io/v1alpha1",kind:"AccessBinding",metadata:{name:"trial-region-maintainers",namespace:"asservat-system"},spec:{effect:"Allow",subjects:[{kind:"Group",issuer:$issuer,id:$group}],roles:["workload-maintainer"],scope:{clusterID:$cluster,namespaceRef:{name:$ns,uid:$nsUID},workloads:[{kind:"Deployment",name:$workload,uid:$workloadUID}]},reason:"Explicit context-only homelab trial"}}' \
  > regional-maintainers.json
kubectl --context "$HUB_CONTEXT" create -f regional-maintainers.json
"$ASSERVAT" installer-cluster-join --context "$HUB_CONTEXT" --namespace asservat-system \
  --join regional-join.json --standby 2 --captures 1
```

The join verifies the original offer, epoch, staged connector and image, then writes guarded trust/catalog/topology/download-path configuration. It does not supply the policy, pool extension or human AccessBinding. The explicit original Kubernetes administrator must retain access for these management operations. A successful CLI exit still needs current runtime/source readiness before a capture is possible.

## Complete and observe the first workflow

Sign in as a member of `TRIAL_GROUP_ID`. Open `/processing` and choose **Initialize processing** if it has not been initialized; this needs the configured processing-operator assignment. Then open `/captures/new`:

1. Enter `$CLUSTER`, `$WORKLOAD_NS`, kind **Deployment** and `$DEPLOYMENT`.
2. Choose **Find diagnostics**, then **Review collection** for pod status.
3. Review the target, purpose and effective retention; choose **Collect pod status**.
4. Open the published result and download its native file before the original 300-second default expires. Check the actual file and its provided SHA-256; a success notification alone is insufficient.

Record source image/chart versions, provider versions, actual result/latency, original expiry, capture/result IDs, downloaded byte count and terminal cleanup. Do not copy evidence or credentials into public logs. Verify that new reads fail at expiry and that cleanup subsequently completes under original managed bounds. Keep a denied/unavailable distinction: entitlement/capacity/provider unavailability is not a successful capture. If any stage fails, preserve its fixed stage code and original identities; do not silently select a replacement Pod or extend retention to conceal timing.

On an interrupted/failed hook, first observe the exact original Pod. A Helm timeout is unknown, not permission to delete or replace a live runner. Only after positive terminal failure/interruption:

```sh
"$ASSERVAT" installer-resume --context "$HUB_CONTEXT" \
  --namespace asservat-bootstrap --name asservat
```

Then repeat the **same** Helm command and original inputs. Never use Helm rollback, forced hook deletion, namespace deletion, new IDs, changed image or edited journals as recovery. Uninstall does not erase CRDs, evidence or outstanding obligations. This is not a restore procedure.

## Current limits

The reference run covers the named short context journey, not one-hour renewal, sustained operation, a second workload cluster, general upgrades/rollback or disaster recovery. The same-context path uses a hub Helm release followed by the regional CLI; a combined single-release installer is not qualified. Registry pulls and provider-specific S3 IAM issuance remain operator tasks; the latter includes a time-sensitive post-bootstrap step. Dependencies are operated separately. This procedure is not a supported release.
