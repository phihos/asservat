# Connector identity

C-04/C-21 under REQ-FED-001, ADR-330 D2/D3 and [ADR-334](../decisions/334-connector-workload-identity.md).

Each workload cluster has one standing connector identity: the cluster's name
in the hub's `clusters` values. Connector process restarts and replicas reuse
it; there is no per-process identity, no certificate and no expiry that forces
renewal.

Hub owners read the accepted owner configuration from PostgreSQL. The source role inserts each new immutable revision. A database trigger appends its digest and generation to `audit_event` in the same transaction, including revisions written by an older worker during an upgrade. The migration records previously retained revisions at migration time. The trigger runs with its installer-defined owner, a fixed `search_path` and a schema-qualified audit destination. [PostgreSQL function privileges](https://www.postgresql.org/docs/18/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY)

## Registration

1. An administrator adds the cluster to the hub's `clusters` values with its
   ServiceAccount token issuer (and, when the hub cannot reach the issuer,
   its JWKS) and runs `helm upgrade`. The hub derives the cluster ID from the
   name.
2. The workload cluster's release (`mode: cluster`) receives only `hub.url`
   and, for a private CA, `hub.caBundle`. No Secret is copied between
   clusters.
3. There is no other registration path: no console page, API operation,
   CLI command or join token. The JWKS is public key material any
   administrator of the workload cluster can read
   (`kubectl get --raw /openid/v1/jwks`).

## Authentication

The connector presents its projected ServiceAccount token (audience: the hub
URL) on every request of its connection. The hub verifies signature (OIDC
discovery of the issuer, or the static JWKS), `iss`, `aud`, expiry and
`sub = system:serviceaccount:<namespace>:<account>`, and attributes the
connection to that cluster. Discovered JWKS are cached and refreshed on an
unknown `kid`; the kubelet rotates the token. Removing the cluster from
`clusters` or setting `revoked: true` replaces the federation Deployment,
closing its old connections. The new Pods accept tokens from the current
registrations. Before listening, each Pod prunes withdrawn AccessBinding
deliveries for the installation’s permission root. If a delivery was removed,
the transaction ends the current permission-stream lease and signals the
reconciler to read the remaining deliveries. Concurrent federation starts
with the same registrations leave an already reconciled stream alone.

The `connector-delivery` SQL role may execute this withdrawal operation.
The function qualifies its objects, locks its search path to `pg_catalog,
pg_temp`, and revokes the default public execution grant in its migration.
The permission reconciler retains ownership of accepted assignments and audit.
[PostgreSQL function privilege guidance](https://www.postgresql.org/docs/18/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY).

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
