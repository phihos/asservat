# ADR-122: Separate private native owner listener

> Superseded in whole or in part by [ADR-330](330-event-driven-system-design.md) (event-driven system design, 2026-11-14). Where this record prescribes polling, expiring freshness windows, per-request Jobs, private PKI or enrollment layers, object-store audit, spent-on-uncertain accounting or installer-era guards, ADR-330 applies.

> Superseded in part by ADR-328 (2026-11-13): The protected `deployment.json` with worker-cluster/control-namespace API pins and retention-topology pins becomes Helm-rendered configuration read by fixed name. The separate listener, connector mTLS, the narrow native-read SQL credential and socket bounds remain valid.

Status: accepted; component implementation and selected native qualification
recorded in [implementation progress](../implementation-progress.md).

The credential enrollment channel and native evidence exchange have different protocols and roles. The enrollment receiver remains unchanged. An optional `nativePort` in the audited owner configuration binds a separate HTTP/2, TLS 1.3 listener to the same activated owner Pod/process. Zero/absence preserves the exact historical configuration/registration JSON and disables native serving. A nonzero port is distinct from the enrollment port, is covered by the existing source digest/acceptance, and uses independently checked existing Pod addresses rather than a user-selected endpoint or second discovery service.

The owner presents its existing process-owned **server-purpose** certificate. The native listener authenticates connector client certificates using protected connector roots and current fleet registration. A connector's clientAuth certificate cannot act as its worker-facing server certificate. The concrete producer and supervisor for that separate connector server identity remain required; neither a test issuer nor a fixture callback fills that boundary.

Mounted Helm-rendered configuration optionally supplies connector public roots and the worker-cluster/control-namespace API endpoints. A separate `sql-native-read.json` credential provides native locator/worker/certificate/current-authority reads and necessary narrow row locks. It exposes no admission, key binding, slot consumption, source acceptance, enrollment signing or retirement writes. Fixed per-cluster/namespace API-token projections provide independent current Pod proof; no forwarded human token or serialized identity is accepted.

The listener bounds sockets before TLS, allows h2 only, one conversation per accepted socket, at most one simultaneous h2 stream, bounded headers/flow-control buffers and an original ten-second socket lifetime. Native operation/proof authority still expires within its original five seconds and may shorten. Stop closes both directions and joins actual request work. Installed native input absence is not inferred from an unavailable provider; it is an explicit disabled configuration.

No public download route follows from private listener construction. The runtime retains the actual original hub request closure and registers only its own installation/Pod/process identity. SQL still independently admits the exact worker/source/operation, and the hub never gains raw unwrap authority. The first wire remains the bounded 4096-byte context slice; a long-lived large-file conversation requires separately qualified fresh segment/lease handling and finite backing, not an extension of old frame authority.
