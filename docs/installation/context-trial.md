# Install with external services

Install Asservat with your own PostgreSQL, S3-compatible object store, OpenBao
and Keycloak, then run the same pod-status capture as the
[quick trial](small-profile.md). You can mix: keep any service bundled and
replace only some.

**Not qualified yet.** The Helm chart supports each external service, but
only the all-bundled install has passed the installed journey. There is no
supported release; build the images as in the
[quick trial](small-profile.md#build-and-push-the-images).

## Prepare the services

Prepare each service as its section in [Install with Helm](helm.md) describes:

1. [PostgreSQL](helm.md#external-postgresql): an existing database with TLS,
   and a Secret with the administrator `credentials.json` that setup uses.
2. [Object store](helm.md#external-object-store): audit and evidence buckets
   and one `<name>-s3-<principal>` Secret per principal.
3. [OpenBao](helm.md#external-openbao): the mounts, keys, PKI roles, policies
   and Kubernetes auth roles.
4. [Keycloak](helm.md#external-keycloak): the confidential console client, the
   `asservat-api` audience, the `asservat_groups` mapper and the default
   scopes, plus a Secret with the client secret.

Create these Secrets in the release namespace before you install, and give the
namespace Pod Security `restricted`.

## Write the values

Start from the [site example](../../examples/helm/context-trial-site.example.yaml)
and merge it after the
[trial profile](../../examples/helm/context-trial-profile.yaml). The parts that
select the external services look like this:

```yaml
mode: combined
origin: https://asservat.example.invalid
identity:
  issuer: https://id.example.invalid/realms/company
  clientID: asservat-console
  browserAudience: asservat-api
  clientSecret: {existingSecret: oidc-client}
  eligibleGroups: [STABLE_USERS_GROUP_ID]
  processingOperators:
    - {clientID: asservat-console, issuer: https://id.example.invalid/realms/company,
       kind: Group, id: STABLE_OPERATORS_GROUP_ID}
fleet:
  issuer: https://id.example.invalid/realms/company
  clients: [asservat-console]
  groups: [STABLE_USERS_GROUP_ID]
exposure:
  service: {type: ClusterIP}
  tls: {mode: proxy}
  ingress:
    enabled: true
    className: nginx
    tls: [{hosts: [asservat.example.invalid], secretName: console-tls}]
region:
  enabled: true
services:
  postgres:
    provider: external
    external: {host: postgres.example.invalid, database: asservat, adminSecret: postgres-admin}
  objectStore:
    provider: external
    external: {endpoint: "https://s3.example.invalid", region: us-east-1,
               bucket: asservat-audit, evidenceBucket: asservat-evidence}
  keyService:
    provider: external
    external: {endpoint: "https://bao.example.invalid"}
```

`exposure.service.type: ClusterIP` overrides the trial profile's NodePort,
because the Ingress reaches the Service in the cluster.

## Install

Pass each CA bundle as a file:

```sh
kubectl apply --server-side --field-manager=asservat-crd-upgrade -f charts/asservat/crds
helm upgrade --install asservat ./charts/asservat -n asservat-system \
  -f examples/helm/context-trial-profile.yaml -f site-values.yaml \
  --set-file identity.providerRootsPEM=idp-ca.pem \
  --set-file services.postgres.external.rootsPEM=postgres-ca.pem \
  --set-file services.objectStore.external.rootsPEM=s3-ca.pem \
  --set-file services.keyService.external.rootsPEM=bao-ca.pem
kubectl -n asservat-system wait --for=condition=Complete --timeout=15m \
  job -l app.kubernetes.io/component=setup
```

If a Job fails, see [troubleshoot](helm.md#troubleshoot).

## Capture pod status

Follow the quick trial from
[initialize processing](small-profile.md#initialize-processing) onward. Use
your issuer and a stable group ID from your realm in the AccessBinding.
