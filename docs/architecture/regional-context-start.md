# Connector connection and regional context start

Each region's connector (A-CONN) holds one outbound, multiplexed HTTP/2
connection to the hub with mutual TLS ([ADR-330](../decisions/330-event-driven-system-design.md)
D2). Hub commands, cluster-state pushes, live rows and download bytes are
separate streams on that connection. This document defines the connection and
the regional half of a context start. Identities are defined in
[peer identity](peer-identity.md).

## Connection

- The connector dials the hub Service and authenticates with its cluster
  client certificate. The hub verifies the chain against the installation CA
  and reads the cluster ID from the certificate. Authentication happens once
  per TLS handshake; streams on the connection need no further peer proof.
- The hub replica that accepts the connection records it in one SQL row
  (`cluster_connection`: cluster ID, replica, connection ID, connected-at).
  A replica that needs to reach a cluster reads that row and forwards the
  request to the holding replica over hub mTLS, or serves it locally. The row
  is replaced on reconnect and removed on clean close; a row naming a replica
  that no longer exists is replaced by the next connection.
- The connector reconnects only after the connection fails, with exponential
  backoff (1 s doubling to 60 s, with jitter; hub load after an outage grows
  with cluster count, as in client-go/gRPC). There is one connection per
  cluster; no idle pools or periodic re-dials.
- The first frame on the connection is `Hello`: cluster ID, connector
  version and a capability list. The hub sends only commands whose capability
  the connector announced. Decoders ignore unknown fields; a field whose
  absence changes meaning is introduced behind a capability. This gives the
  documented N−1 skew between hub, connector and node collectors (R-10; test
  cost grows with each supported version, as in the Kubernetes skew policy).
- Every stream has its own deadline from the operation that opened it and
  byte/frame ceilings derived from its message schema (see Ceilings). Cancelling the originating
  operation resets the stream; resetting a stream cancels the work it carried
  on the other side.

## Cluster-state pushes

The connector runs shared informers (LIST once, then WATCH) for the
namespaces, workloads, Pods, Nodes, EndpointSlices, AccessBindings and
permission sources the hub needs, and pushes changes as deltas on a state
stream. Each delta carries a per-kind sequence number. After a reconnect the
connector sends a digest per kind; the hub requests a full resend only for
kinds whose digest differs. While the connection is down, the hub marks that
cluster's state unavailable; it does not expire it on a timer while the
connection is up.

Target resolution reads this pushed state (or the connector's own cache for
cluster-local operations); see [workload target resolution](workload-target-resolution.md).

## Context start

The hub runs `APIContextRunner` ([ADR-171](../decisions/171-hub-run-context-execution.md)).
`RegionalAPIContextStart` authorizes the operation once
([ADR-311](../decisions/311-operation-authority-recheck.md)), reserves the
cluster capture capacity with the operation's idempotency key and opens a
command stream to the cluster. The stream carries the capture, attempt,
target, scope/expectation/budget digests, capability and the operation
deadline. Groups, scopes and public tokens never leave the hub.

The region answers, in order and only for that stream's capture, the
cluster-local operations: resolve Pod (or `resolve-packet-source` for a policy
executor), read process, prepare/ready/consume start, prepare output, acquire
context and complete stored. Plaintext and data keys stay in the region; only
acquisition instants, copy receipts and a finite disposition cross. Native
bytes and raw errors do not. Publication follows [context publication](context-publication.md).

Each regional operation verifies the target Pod UID once at its effect and
never substitutes a replacement Pod. A retry uses the same idempotency key;
the region returns the stored outcome for a key it has already executed.
An unknown outcome is resolved by looking the key up ([ADR-330](../decisions/330-event-driven-system-design.md) D7).
If the connection drops, the hub resends the accepted, non-terminal context
start after the connector reconnects (I-01), and the region continues from
the stored outcome of each operation it has already executed.

`start-policy-recording` carries the SQL observation receipt and the exact
source returned by `resolve-packet-source`. The region checks that the
expectation digest matches the stream's, derives the program digest from the
frozen instructions and starts the node queue for that source without a
second Pod or node resolution. Raw predicates stay refused until their
separate qualification.

The connector process trusts its mounted configuration and ServiceAccount
([ADR-328](../decisions/328-administrator-only-namespaces.md)); it performs no
self-verification of its Deployment, Pod chain, settings objects or admission
policies before serving an operation.

## Ceilings

| Item | Bound | Reason |
| --- | --- | --- |
| Command and control frame | 64 KiB canonical | Largest command (`start-policy-recording`) carries a 4096-instruction classic-BPF program (32 KiB, `BPF_MAXINSNS`) plus its envelope; same ceiling as the [native exchange](native-exchange.md) |
| Operation request/reply | 64 KiB canonical each | Same derivation: `resolve-packet-source` and the recording start carry the compiled program |
| Context-start stream | The fixed operation sequence above (eight operations, one request and one reply frame each, plus the command and the final disposition); at most 2 MiB in total | Operation count follows from the sequence; 2 MiB is the connector's Kubernetes API response cap (an etcd object is at most 1.5 MiB plus JSON overhead) |
| Concurrent captures per cluster | Capture capacity of the cluster (C-07), at least 8, default derived from cluster size | Storm protection, maintainer decision ([ADR-335](../decisions/335-usable-by-default.md) D8) |
| Connector settings | Kubernetes ConfigMap/Secret limit (1 MiB) | External object limit; no separate cap |

## Capture history metadata

Capture-history control metadata (settings, save reasons, filters) is stored
as ordinary hub SQL rows under the existing authorization
([ADR-330](../decisions/330-event-driven-system-design.md) D8). It does not
travel to the region and has no object-store envelopes.

## Ownership

C-20 owns the wire DTOs and `internal/transport/contextstart`. C-21 owns the
adapter and bootstrap composition. Application and domain imports stay
inward; adapters never import transport handlers.
