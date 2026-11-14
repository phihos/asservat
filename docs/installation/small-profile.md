# Quick trial with bundled services

> **Target workflow** of [ADR-335](../decisions/335-usable-by-default.md); see the note at the top of [Install with Helm](helm.md).

Install Asservat in one Kubernetes cluster with every service bundled, then
capture and download the pod status of one of your Deployments. One Helm
release runs the hub and the workload roles (`mode: combined`, the default).
[Install with Helm](helm.md) is the reference for every value used here.

This trial has no high availability for the bundled services, and its
backups stay on the cluster's storage until you add an off-cluster repository
([back up](helm.md#back-up)).

## Before you start

You need:

- Kubernetes 1.30 or newer with a default StorageClass, Helm and kubectl.
- One DNS name for the console, for example `asservat.lab.example`, routed by
  an Ingress controller, and a TLS Secret or cert-manager issuer for it.
- A registry every node can pull from, until a release exists.

On kind or another cluster whose nodes share a workstation's kernel, add
`--set collector.enabled=false`; pod-status capture does not need the node
collector.

## Build and push the images

Until a release exists, build the images from the repository root:

```sh
REGISTRY=registry.example.invalid
TAG=$(git rev-parse --short=12 HEAD)
make image IMAGE="$REGISTRY/asservat:$TAG"
tar -c packaging/postgres |
  docker build -f packaging/postgres/Dockerfile -t "$REGISTRY/asservat-postgres:$TAG" -
docker push "$REGISTRY/asservat:$TAG"
docker push "$REGISTRY/asservat-postgres:$TAG"
```

## Install

Save this as `site-values.yaml`:

```yaml
image: {repository: registry.example.invalid/asservat, tag: TAG}
origin: https://asservat.lab.example
exposure:
  ingress:
    enabled: true
    className: nginx
    tls: {secretName: asservat-tls}
services:
  postgres:
    bundled: {image: {repository: registry.example.invalid/asservat-postgres, tag: TAG}}
  identity:
    provider: keycloak
    keycloak:
      initialUsers:
        - {username: alice, groups: [/asservat-users, /asservat-admins]}
administrators:
  groups: [/asservat-admins]
```

Install and wait:

```sh
helm upgrade --install asservat ./charts/asservat \
  -n asservat-system --create-namespace -f site-values.yaml \
  --wait --wait-for-jobs --timeout 15m
```

When the command returns, setup has created the realm, initialized
processing and started every workload. If it fails, see
[troubleshoot](helm.md#troubleshoot).

## Sign in

Read alice's one-time password:

```sh
kubectl -n asservat-system get secret asservat-keycloak-users \
  -o jsonpath='{.data.alice}' | base64 -d
```

Open `https://asservat.lab.example`, sign in as `alice` and set a new
password. To add more users later, extend `initialUsers` and run the same
`helm upgrade`, or use the Keycloak admin console at `<origin>/idp/admin/`;
the NOTES print the command that reads its bootstrap password.

## Capture pod status

The default budget policy already covers your application namespaces. Grant
the users group maintainer rights on one Deployment:

```sh
kubectl apply -f - <<'EOF'
apiVersion: asservat.io/v1alpha1
kind: AccessBinding
metadata: {name: trial-maintainers, namespace: my-app}
spec:
  effect: Allow
  subjects: [{kind: Group, name: /asservat-users}]
  roles: [workload-maintainer]
  workloads: [{kind: Deployment, name: my-app}]
EOF
```

The AccessBinding lives in the application namespace it grants
([grant teams access](helm.md#grant-teams-access)).

Open **New capture**, pick the cluster and your Deployment, then **Find
diagnostics**, **Review collection** and **Collect pod status**. Open the
result and download its native file. Evidence is kept for 14 days by default
(`retention.evidence`). Copies you download stay yours to manage.

## Replace one bundled service

Each service is selected on its own. To use your existing PostgreSQL, object
store, identity provider or OpenBao, set `services.<service>.provider` and
follow the matching section of
[Install with Helm](helm.md#choose-bundled-or-external-services).
