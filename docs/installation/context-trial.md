# Install with external services

> **Target workflow** of [ADR-335](../decisions/335-usable-by-default.md); see the note at the top of [Install with Helm](helm.md).

Install Asservat with your own PostgreSQL, S3-compatible object store and
OpenID Connect provider, then run the same pod-status capture as the
[quick trial](small-profile.md). You can mix: keep any service bundled and
replace only some. OpenBao is optional; the default local key service needs
no external service.

There is no supported release yet; build the images as in the
[quick trial](small-profile.md#build-and-push-the-images).

## Prepare the services

Prepare each service as its section in [Install with Helm](helm.md) describes:

1. [PostgreSQL](helm.md#external-postgresql): a database reachable over
   TLS 1.2 or newer, and either a `CREATEROLE` login for setup or the
   pre-created logins.
2. [Object store](helm.md#external-object-store): one bucket and one
   credential limited to it, or your platform's workload identity.
3. [Identity provider](helm.md#external-keycloak): a confidential console
   client with the redirect URI `<origin>/auth/callback`, an audience mapper
   and the `groups` claim, plus a Secret with the client secret.
4. Optional: [OpenBao](helm.md#external-openbao) with one transit key, policy
   and role, or an admin token for setup.

Create the Secrets in the release namespace before you install. CA bundles are
needed only for services with a private CA.

## Write the values

```yaml
image: {repository: registry.example.invalid/asservat, tag: TAG}
origin: https://asservat.example.invalid
identity:
  issuer: https://id.example.invalid/realms/company
  clientID: asservat-console
  clientSecret: {existingSecret: oidc-client}
administrators:
  groups: [/asservat-admins]
exposure:
  ingress:
    enabled: true
    className: nginx
    tls: {secretName: console-tls}
services:
  identity: {provider: external}
  postgres:
    provider: external
    external: {host: postgres.example.invalid, database: asservat, adminSecret: postgres-admin}
  objectStore:
    provider: external
    external: {endpoint: "https://s3.example.invalid", region: us-east-1,
               bucket: asservat, existingSecret: asservat-s3}
capacity:
  evidenceStorage: 500Gi
```

`capacity.evidenceStorage` is the share of the bucket Asservat may fill; the
other capacity and retention defaults apply unchanged
([capacity and retention](helm.md#capacity-and-retention)).

## Install

```sh
helm upgrade --install asservat ./charts/asservat \
  -n asservat-system --create-namespace -f site-values.yaml \
  --wait --wait-for-jobs --timeout 15m
```

If it fails, see [troubleshoot](helm.md#troubleshoot).

## Capture pod status

Follow the quick trial from [capture pod status](small-profile.md#capture-pod-status)
onward, with a group name from your provider in the AccessBinding.
