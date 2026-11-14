# Connector identity

C-04/C-21 under REQ-FED-001 and ADR-330 D2/D3.

Each workload cluster has one connector identity. Connector process restarts
and replicas reuse it; there is no per-process identity.

## Registration and first certificate

1. An administrator registers the cluster. The hub creates a `cluster`
   row and a one-time bootstrap token, shows the token once and stores only
   its hash and expiry.
2. The connector Helm release receives the token in a Secret.
3. The connector generates a P-256 key, sends a certificate signing request
   with the token over TLS to the hub, and receives a client certificate for
   the cluster identity from the installation CA. The hub consumes the token
   in the same transaction that records the certificate serial and writes the
   audit row (D6). A retry with the same token and public key returns the
   same certificate.
4. The connector stores key and certificate in its own Secret.

## Rotation and revocation

The connector sends a new CSR over its authenticated connection at about
two thirds of the certificate lifetime and switches to the new certificate
on success. Revoking a cluster disables its `cluster` row; the hub checks
the row when a connection is established and closes open connections of a
disabled cluster when the change event arrives (D1).

## Connection

The connector holds one outbound, multiplexed mTLS connection to the hub
(D2). Commands, cluster-state pushes ([cluster observations](cluster-observations.md)),
live rows and download bytes are streams on it. The hub records which
replica holds the connection in SQL and routes work for that cluster
there.

In-cluster Asservat workloads (node collectors, regional readers)
authenticate to the connector with an audience-bound projected
ServiceAccount token checked once per connection by TokenReview.

Precedent: kubelet TLS bootstrapping and client certificate rotation;
Open Cluster Management klusterlet registration; Kubernetes konnectivity.
