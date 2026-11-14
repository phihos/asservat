# Quick trial with bundled services

Install Asservat in one Kubernetes cluster with bundled PostgreSQL, OpenBao,
SeaweedFS and Keycloak, then capture and download the pod status of one of
your Deployments. One Helm release runs the hub and the workload region
(`mode: combined`); no node collector is installed.

**Developer trial, no supported release.** You build the images from source.
This configuration passes the full kind journey in
`test/integration/helm_native_kind_test.go`; see the
[implementation ledger](../implementation-progress.md). It has no high
availability, and backups on the same storage are not disaster recovery.
[Install with Helm](helm.md) is the reference for every value used here.

## Before you start

You need:

- Kubernetes 1.35 or newer, Helm, kubectl, jq and Docker.
- The Go and Node versions from `go.mod` and `web/package.json`, plus a C
  compiler, make, flex, bison, curl, tar, xz and `file` for the static
  libpcap build.
- A registry every node can pull from.
- A StorageClass. This page uses small sizes; the chart defaults are larger.
- Two HTTPS endpoints reachable from browsers and Pods: the console (this page
  uses NodePort 31450) and Keycloak (NodePort 31451), with serving
  certificates for their names and the CA as `ca.pem`.

## Build and push the images

From the repository root:

```sh
REGISTRY=registry.example.invalid
REV=$(git rev-parse --short=12 HEAD)
make image IMAGE="$REGISTRY/asservat:$REV"
tar -c packaging/postgres |
  docker build -f packaging/postgres/Dockerfile -t "$REGISTRY/asservat-postgres:$REV" -
docker push "$REGISTRY/asservat:$REV"
docker push "$REGISTRY/asservat-postgres:$REV"
```

Note the `digest: sha256:…` line of each push. The chart references images
only by registry manifest digest; a local image ID is not one.

## Prepare the namespace

Create the namespace with Pod Security `restricted`, the two TLS Secrets and
the CRDs:

```sh
kubectl create namespace asservat-system
kubectl label namespace asservat-system pod-security.kubernetes.io/enforce=restricted
kubectl -n asservat-system create secret tls console-tls --cert=console.crt --key=console.key
kubectl -n asservat-system create secret tls keycloak-tls --cert=keycloak.crt --key=keycloak.key
kubectl apply --server-side --field-manager=asservat-crd-upgrade -f charts/asservat/crds
```

## Write the values

Save this as `site-values.yaml` and replace the host names and digests. The
`processingOperators` entry is a placeholder until the realm exists:

```yaml
mode: combined
image:
  repository: registry.example.invalid/asservat
  digest: sha256:PRODUCT_DIGEST
origin: https://asservat.lab.example.invalid:31450
identity:
  clientID: asservat-console
  browserAudience: asservat-api
  clients:
    - {id: asservat-console, kind: human, classQualified: true}
    - {id: asservat-mcp, kind: human, classQualified: true}
  eligibleGroups: []
  processingOperators:
    - {clientID: asservat-console, issuer: https://login.lab.example.invalid:31451/realms/asservat,
       kind: User, id: 00000000-0000-4000-8000-000000000001}
exposure:
  tlsSecret: console-tls
fleet:
  clients: [asservat-console, asservat-mcp]
  groups: []
region:
  enabled: true
services:
  postgres:
    provider: bundled
    bundled:
      image: registry.example.invalid/asservat-postgres@sha256:POSTGRES_DIGEST
      dataSize: 2Gi
      backupSize: 2Gi
  keyService:
    provider: openbao
    openbao: {persistence: {size: 1Gi}}
  objectStore:
    provider: seaweedfs
    seaweedfs: {persistence: {size: 2Gi}}
  identity:
    provider: keycloak
    keycloak:
      hostname: https://login.lab.example.invalid:31451
      tlsSecretName: keycloak-tls
      processingOperators: true
      service: {type: NodePort, nodePort: 31451}
      database: {host: ""}
```

`database.host: ""` puts Keycloak's database on the bundled PostgreSQL. Set
`storageClass` under each bundled service if your cluster has no default.

## Install

The [trial profile](../../examples/helm/context-trial-profile.yaml) supplies
the capacity, retention and connector limits that combined mode needs, and
exposes the console as NodePort 31450:

```sh
helm upgrade --install asservat ./charts/asservat -n asservat-system \
  -f examples/helm/context-trial-profile.yaml -f site-values.yaml \
  --set-file identity.providerRootsPEM=ca.pem
kubectl -n asservat-system wait --for=condition=Complete --timeout=15m \
  job -l app.kubernetes.io/component=setup
```

Read the generated group IDs:

```sh
USERS=$(kubectl -n asservat-system get secret asservat-keycloak-state \
  -o jsonpath='{.data.users-group-id}' | base64 -d)
OPERATORS=$(kubectl -n asservat-system get secret asservat-keycloak-state -o json |
  jq -r '.data["asservat-realm.json"] | @base64d | fromjson
    | .groups[] | select(.name == "asservat-processing-operators") | .id')
```

In `site-values.yaml`, set `identity.eligibleGroups` and `fleet.groups` to
`[USERS]`, and replace the placeholder operator with
`{kind: Group, id: OPERATORS}` (same `clientID` and `issuer`). Run the same
`helm upgrade` and wait for the new setup Job.

If a Job fails, see [troubleshoot](helm.md#troubleshoot).

## Create your user

Read the Keycloak administrator password:

```sh
kubectl -n asservat-system get secret asservat-keycloak-state \
  -o jsonpath='{.data.bootstrap-admin-password}' | base64 -d
```

Sign in at `https://login.lab.example.invalid:31451/admin/` as
`asservat-bootstrap-admin`, open realm `asservat`, create your user with a
password and add it to `asservat-users` and `asservat-processing-operators`.
Do not change the groups' `asservat_group_id` attributes.

## Initialize processing

Sign in at the origin, open `/processing`, choose **Refresh processing rules**
and then **Initialize processing**. Captures stay unavailable until this is
done.

## Capture pod status

The trial profile's EvidenceBudgetPolicy covers namespaces labelled
`asservat-trial=true` in this cluster. Label your workload namespace and grant
the users group maintainer rights on one Deployment:

```sh
NS=my-app
DEPLOYMENT=my-app
CLUSTER=$(kubectl -n asservat-system get secret asservat-ids \
  -o jsonpath='{.data.clusterID}' | base64 -d)
kubectl label namespace "$NS" asservat-trial=true
jq -n --arg cluster "$CLUSTER" --arg ns "$NS" \
  --arg nsUID "$(kubectl get namespace "$NS" -o jsonpath='{.metadata.uid}')" \
  --arg app "$DEPLOYMENT" \
  --arg appUID "$(kubectl -n "$NS" get deployment "$DEPLOYMENT" -o jsonpath='{.metadata.uid}')" \
  --arg issuer https://login.lab.example.invalid:31451/realms/asservat --arg group "$USERS" \
  '{apiVersion:"asservat.io/v1alpha1",kind:"AccessBinding",
    metadata:{name:"trial-maintainers",namespace:"asservat-system"},
    spec:{effect:"Allow",subjects:[{kind:"Group",issuer:$issuer,id:$group}],
      roles:["workload-maintainer"],
      scope:{clusterID:$cluster,namespaceRef:{name:$ns,uid:$nsUID},
        workloads:[{kind:"Deployment",name:$app,uid:$appUID}]},
      reason:"Pod-status trial"}}' | kubectl create -f -
```

Open `/captures/new`, choose the cluster and your Deployment, then **Find
diagnostics**, **Review collection** and **Collect pod status**. Open the
result and download its native file. The profile keeps evidence for 300
seconds by default, then deletes it within a further 300 seconds. Copies you
download stay yours to manage.

## Replace one bundled service

Each service is selected on its own. To use your existing Keycloak, PostgreSQL,
object store or OpenBao, set `services.<service>.provider: external` and
follow the matching section of
[Install with Helm](helm.md#choose-bundled-or-external-services). These mixed
combinations are not qualified yet.
