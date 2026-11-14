# ADR-334 — Connectors authenticate with their cluster's ServiceAccount tokens

Date: 2026-11-14. Status: accepted (maintainer decision: copying a Secret
from the hub to a workload cluster is a no-go; "Let's go with your
recommendation"). Supersedes the join Secret, the one-use bootstrap record and
connector certificate enrollment of ADR-331 and ADR-330 D3's connector
bootstrap, and the four separately exposed connector endpoints of ADR-331.

## Decision

1. **Credential.** A connector authenticates every request on its hub
   connection with a projected ServiceAccount token of its own cluster
   (audience: the hub URL, kubelet-rotated, short-lived). Nothing is copied
   from the hub to the workload cluster.
2. **Trust.** The hub's values register each workload cluster with public
   data only:

   ```yaml
   clusters:
     - name: eu
       clusterID: <uuid>
       issuer: https://eu-apiserver.example     # the member's ServiceAccount issuer
       # jwks: '<kubectl get --raw /openid/v1/jwks>'  # when the hub cannot reach the issuer
       # connector: asservat-system/asservat-connector  # default namespace/ServiceAccount
   ```

   The hub verifies signature (OIDC discovery of the issuer, or the static
   JWKS), `iss`, `aud`, expiry and `sub =
   system:serviceaccount:<namespace>:<account>`, and attributes the
   connection to that cluster. A token from any other subject, issuer or
   audience is refused. JWKS from discovery are cached and refreshed on an
   unknown `kid` (ADR-330 D1); static JWKS change with the values.
3. **One endpoint behind ordinary exposure.** The connector reaches the hub at
   one HTTPS URL (`hub.url`), the same public endpoint as the console or a
   separate host name, through any Ingress or Gateway, including one that
   terminates TLS. Commands, cluster-state pushes, live rows and evidence
   uploads are streams on that one multiplexed HTTP/2 connection (ADR-330 D2);
   the hub writes uploaded evidence to the object store. The connector trusts
   the hub's certificate through the system roots or a public `hub.caBundle`
   value.
4. **Settings from the hub.** On connect the connector receives the hub's
   settings it needs (installation and cluster IDs, protocol capabilities,
   limits); later changes are pushed on the connection. No offer is copied
   and no restart is needed.
5. **Fallback join token.** For a cluster whose ServiceAccount public keys the
   hub cannot obtain, the hub issues a kubeadm-style token
   (`<id>.<secret>`, default validity 24 h, reusable within it) shown once in
   the console or by a CLI command, passed to the member's chart as one value
   together with the hub CA certificate hash. The connector uses it only to
   register its ServiceAccount public keys with the hub; afterwards it
   authenticates as in 1.
6. **Optional mTLS.** Where the hub is exposed by TLS passthrough, connectors
   may additionally use client certificates the hub signs for a CSR
   authenticated by the ServiceAccount token (kubelet TLS bootstrapping
   pattern). It adds no copied material and is not required.

## Why not mTLS by default

A client certificate authenticates the connector only when the hub itself
terminates TLS. A TLS-terminating Ingress or Gateway stops it, and forwarding
it is proxy-specific (nginx-ingress `auth-tls-pass-certificate-to-upstream`,
Envoy XFCC). The maintainer requires that the proxy may terminate TLS.
Bearer tokens pass through any proxy.

## Precedent

- Vault/OpenBao JWT auth with a Kubernetes cluster as OIDC provider: discovery
  URL or static public keys
  ([Vault docs](https://developer.hashicorp.com/vault/docs/auth/jwt/oidc-providers/kubernetes)).
- Cloud workload identity federation (EKS IRSA, GKE fleet workload identity)
  trusts a cluster's ServiceAccount issuer instead of distributing secrets.
- kubeadm join tokens with CA hash pinning for the fallback
  ([kubeadm join](https://www.kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-join)).
- kubelet TLS bootstrapping and Open Cluster Management registration for the
  optional certificate path.

## Consequences

- Removed: join Secrets, the bootstrap record and its five-minute validity,
  bootstrap reservations/issuance for connectors, connector certificate
  enrollment and renewal, the regional offer ConfigMap/Secret copy, the
  `remote.*` endpoint list and the federation, hub-api native, key-service and
  object-store exposure for connectors.
- Limitation: a cluster whose issuer is unreachable from the hub (for example
  k3s' default in-cluster issuer) needs its public JWKS in the hub's values,
  updated when that cluster rotates its ServiceAccount signing key.
- The hub verifies tokens locally; no TokenReview against the member's API
  server and no hub access to member clusters.

## Complexity gate

1. Every multi-cluster install needed a hand-copied Secret, four exposed
   ports and a restart after hub changes (maintainer: no-go).
2. Not accepted; the maintainer rejected it.
3. All multi-cluster deployments; combined mode uses the same path in-cluster.
4. Above.
5. Fewer credentials: no bootstrap record, connector CA or certificates; the
   hub needs network access to member issuers only when it uses discovery.
6. One degraded state: unknown `kid` with an unreachable issuer (connection
   refused until the JWKS refresh succeeds or the values are updated).
7. Configuration describes topology only (`issuer`, optional `jwks`).
8. Depends on standard Kubernetes ServiceAccount token projection and
   issuer discovery.
9. One signature check per connection setup and token rotation; JWKS cached
   per cluster.
10. Unreleased product: replace the ADR-331 join path without compatibility.
11. A longer-lived bootstrap record would still be a copied Secret.
