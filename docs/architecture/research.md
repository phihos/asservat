# Architecture method, sources and selected refinements

Checked 2026-10-09. These are primary references for architecture organization and relevant platform behavior. They establish available concepts/semantics, not the feasibility or performance of the complete Asservat integration.

| Source | Verified fact | Application to this design |
| --- | --- | --- |
| [C4 diagram types](https://c4model.com/diagrams) | Context, application/container, component and code levels can be supplemented by dynamic/deployment views; use levels that add value. | Context/application diagrams plus selected component and runtime diagrams. Mermaid and Markdown remain repository-native; no modeling service dependency. |
| [arc42 building blocks](https://docs.arc42.org/section-5/) | Hierarchical component descriptions can include responsibility, interfaces, source location and requirement mapping. | A machine-readable ownership/dependency catalog plus concise component contracts. Avoid a class diagram for every entity. |
| [arc42 runtime view](https://docs.arc42.org/section-6/) | Runtime scenarios describe how building blocks interact. | Trace success and failure through state owners, including duplicate starts, revocation and expiry. |
| [Go module layout](https://go.dev/doc/modules/layout) | Go supports internal packages and command-oriented layouts. | One initial Go module, minimal command entrypoint, internal application/domain/adapter packages and per-role composition roots. This exact decomposition is our choice. |
| [PostgreSQL SELECT locking](https://www.postgresql.org/docs/18/sql-select.html) | SKIP LOCKED avoids waiting on locked rows and yields an inconsistent view; it can serve queue-like consumers. | Use it for bounded work claiming only. Admission/fairness remains explicit and transactional under the existing persistence contract. |
| [Kubernetes API concepts](https://kubernetes.io/docs/reference/using-api/api-concepts/) | Resource versions support concurrency/watch behavior and must be treated as opaque. | CAS local control records and reconcile watch/relist freshness; no numeric comparison or claim of multi-object atomicity. |
| [Kubernetes leases](https://kubernetes.io/docs/concepts/architecture/leases/) | Lease objects support coordination such as heartbeats and leader election. | Leader election selects work ownership; application attempt/epoch checks must still fence side effects. A lease is not evidence that an external process stopped. |
| [Linux Unix sockets](https://man7.org/linux/man-pages/man7/unix.7.html) | Unix-domain sockets support local communication and peer-credential mechanisms. | A restricted local core-helper handoff. Credentials do not prove forensic truth against trusted host root or solve PID reuse. |
| [JWS, RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html) | Standard signed-message serializations bind protected headers and payload bytes. | Use a maintained JOSE implementation for signed work, with strict size/key/purpose/algorithm policy and no remote key selection. No custom signature protocol. |
| [Fully specified JOSE algorithms, RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html) | Defines the explicit Ed25519 identifier and deprecates the polymorphic EdDSA identifier. | Select Ed25519 JWS for v1 internal work. Qualify library/key-provider support; unsupported peers cannot silently reinterpret the identifier or downgrade to another algorithm. |

## Design choices

The accepted approach is a modular hub with independently scheduled API/background roles and separate privileged/local/offline roles. A shared Go binary does not make these one security identity. Feature modules remain code modules unless a demonstrated privilege/locality/lifetime/scaling boundary warrants a service. PostgreSQL, Kubernetes and regional objects retain their already accepted authority split.

V1 signed control uses JWS compact serialization, protected `typ=asservat-internal-work+jws`, `alg=Ed25519` and a trusted configured `kid`. The payload is the exact canonical UTF-8 control-work JSON. Validate the decoded payload against the negotiated strict schema, then current authority/freshness/fences; do not use signature validity as sufficient permission. Private hub signing keys and separately delegated cluster signing keys use configured protected key handling and rotation. Node-start tickets have a distinct protected type/purpose and are restricted by the hub delegation and local ceiling. No key/algorithm supplied in an incoming message becomes trusted by itself. Library and key-provider qualification belongs to S-00, including old-key overlap bounded by permit expiry and no use after revocation.

This signing refinement is internal only. It does not change OAuth/OIDC provider algorithms or prescribe the operator's TLS certificate algorithm. It also does not replace streaming evidence encryption. No cryptographic implementation or compatibility test was performed in this documentation pass.

## Reconciled gaps

| Earlier gap | Resolution |
| --- | --- |
| Two illustrative package layouts | One canonical domain/application/adapter/transport layout and explicit dependency catalog |
| Regional evidence index described as a hub process without locality qualification | Regional bounded index hosted with connector initially; hub caching only within allowed locality |
| Controller-to-node interaction unspecified despite no inbound node requirement | Collector-initiated private mTLS plus narrow local reservation/checkpoint methods |
| Leader leases could be mistaken for effect fencing | Stable start identity, durable disposition before effect, no replay on uncertainty |
| Live traffic could be treated as durable control results | Separate transient owner/exchange path with no outbox/SQL row payload |
| Analysis images versus executable/SA ownership unclear | Role-selecting binary, separate image contents and acquire/analyze/publish identities |
| Security work appeared later than generic collectors in task numbering | Implementation slices require authority/audit/privacy/capacity foundations before enabling effects |

All choices are integrated as design, not operational certification. No new product-level ambiguity requires overriding an accepted user decision. Exact environment qualification and measured resource limits remain named implementation gates, not guessed defaults.
