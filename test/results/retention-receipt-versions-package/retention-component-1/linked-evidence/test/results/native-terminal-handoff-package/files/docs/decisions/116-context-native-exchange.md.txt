# ADR-116: purpose-specific regional native context exchange

Status: accepted design; staged implementation and qualification remain explicit.

## Decision

Use an outbound HTTP/2/TLS 1.3, bounded framed I-13 conversation from the exact admitted acquisition worker through its authenticated connector to the original live hub request. The existing pod-status native reader is the first mechanism. Reuse SQL42 response/window accounting, current C02 identity batches, existing encrypted audit and exact-object key services. Add migration 00045's distinct bounded native owner/key/backing facets rather than reusing certificate enrollment locators as evidence authority.

The hub owns current human authorization throughout. No personal credentials or serialized `CurrentIdentity` cross the wire. The connector supplies its actual separately scoped connector client identity; an owner-enrollment certificate cannot stand in for that role. The acquisition worker holds exact-object unwrap authority, while ordinary collectors stay wrap-only and the hub/connector have none.

Preparation, metadata observation and content are separate operation kinds with different existing prepaid parents. Native immutable facts may remain in one bounded process result; payload and unwrapped keys do not. SQL and encrypted audit must positively acknowledge preparation before it becomes observable. Content completion requires the actual final sink count and flush followed by the exact regional acknowledgement. Unknown outcomes remain charged and never authorize a fresh decrypt or silent owner replacement.

## Consequences

There is no broker, generic RPC framework, remotely supplied callback or automatic uncertain POST replay. Each hop owns at most one pending native payload and one bounded next-phase control input, with current checks and the original deadline around every frame. One original five-second setup bound includes Hello, handshake and headers; h2 is required on both the actual client and server.

Known no-command and positively joined success may permit another bounded conversation within the original worker lifetime. Successful v1 Done now requires a positively acknowledged exact original SQL-owner close before its production. This strengthens the existing success condition without changing bytes or adding a retry: nil cleanup, absence, expiry or an unknown result are not positive closure. A private hub-only capability sends that zero-byte terminal marker under the previous complete check’s original deadline after the restrictive close; all nonterminal frames keep ordinary current checks. Router/handler capacity remains held until actual I/O joins. A lost final marker stays uncertain even when SQL closure succeeded. Every other result is uncertain. Lost final acknowledgement currently requires explicit cancellation, positive worker retirement and a separately paid new preparation; automatic same-process metadata reconciliation needs an additional positive closure protocol and is not claimed here.

Finite rows, key slots and update/history backing require protected measured qualification and cleanup before runtime enablement. Expiry and row fencing do not prove quiescence or erase spend. The 4096-byte reader does not establish generic large-artifact throughput, despite SQL42's larger accounting limit. See [native exchange](../architecture/native-exchange.md) for code boundaries, current qualification and remaining composition.

The command frame alone is capped at 640 KiB, covering the existing context expectation/copy bounds; 64 KiB Hello/metadata/ACK and 1 MiB data limits remain. Domain-valid maximal-source Go encoding reproduced the earlier 64 KiB rejection. Native v2 profiles require a provisional 64 MiB memory minimum, pending deployed RSS qualification; the architecture note distinguishes bounded logical buffers from runtime allocation overhead.
