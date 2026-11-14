# Connector identity

C-04/C-21 under REQ-FED-001, ADR-330 D2/D3, ADR-332 (standing connector
identity) and ADR-334 (connector workload identity).

Each workload cluster has one standing connector identity: the cluster's name
in the hub's `clusters` values. Connector process restarts and replicas reuse
it; there is no per-process identity, no certificate and no expiry that forces
renewal.

## Registration

1. An administrator adds the cluster to the hub's `clusters` values with its
   ServiceAccount token issuer (and, when the hub cannot reach the issuer,
   its JWKS) and runs `helm upgrade`. The hub derives the cluster ID from the
   name.
2. The workload cluster's release (`mode: cluster`) receives only `hub.url`
   and, for a private CA, `hub.caBundle`. No Secret is copied between
   clusters.
3. If the hub can neither reach the issuer nor be given its JWKS, an
   administrator issues a kubeadm-style join token (valid 24 hours, the kubeadm
   bootstrap-token default: a single-use secret's exposure grows with its
   lifetime, and a day suits a human handing it over), passed
   to the workload cluster's release with the hub CA certificate hash. The
   connector uses it only to register its cluster's ServiceAccount public
   keys; the hub stores only the token hash and writes an audit row.

## Authentication

The connector presents its projected ServiceAccount token (audience: the hub
URL) on every request of its connection. The hub verifies signature (OIDC
discovery of the issuer, or the static JWKS), `iss`, `aud`, expiry and
`sub = system:serviceaccount:<namespace>:<account>`, and attributes the
connection to that cluster. Discovered JWKS are cached and refreshed on an
unknown `kid`; the kubelet rotates the token. Removing the cluster from
`clusters` or setting `revoked: true` disables its row; the hub refuses its
tokens and closes its open connections when the change event arrives (D1).

## Connection

The connector holds one outbound, multiplexed HTTP/2 connection to the hub's
one HTTPS endpoint, through any Ingress or Gateway including one that
terminates TLS (D2). Commands, cluster-state pushes
([cluster observations](cluster-observations.md)), live rows, evidence uploads
and download bytes are streams on it. The hub records which replica holds the
connection in SQL and routes work for that cluster there.

In-cluster Asservat workloads (node collectors, regional readers)
authenticate to the connector with an audience-bound projected
ServiceAccount token checked once per connection by TokenReview.

Precedent: Kubernetes service account issuer discovery and workload identity
federation (cloud providers accept a cluster's ServiceAccount tokens by its
issuer); Argo CD and Open Cluster Management agents connecting outbound.
