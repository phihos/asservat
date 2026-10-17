# Domain foundation

The [domain guide](../docs/domain/README.md), [typed catalog](../docs/domain/model.yaml) and [implementation mapping](../docs/domain/implementation-mapping.md) define the conceptual foundation for SQL, CRDs and Go. Existing executable wire contracts retain authority over public enums/field shapes.

## REQ-DOM-001 — Identity and authority boundaries

Separate identity-provider principals, Kubernetes configuration, accepted hub execution, node source state and committed evidence. Use typed IDs, immutable Kubernetes UIDs and issuer-scoped subjects; names are display metadata. Domain objects, database rows, CRD spec/status and protocol DTOs are distinct projections with declared write authority. Introduce no tenant or container permission model.

### SC-DOM-001

Given deletion/recreation of a namespace/workload or a recycled PID, when a previous request/history/grant is reused, then identity validation prevents it from silently targeting the new incarnation.

## REQ-DOM-002 — Capture and source lifecycles

Capture, immutable AcceptedScope, ActionAttempt, PolicyActivation, SourceSession and SourceSnapshot are separate concepts. A recording save binds existing sources and immutable first-acceptance end time. Sources have independent leases/budgets/readiness; cancellation or retry of a snapshot neither starts a source nor stops an unrelated recorder. Track uncertain starts separately from terminal user-visible status.

### SC-DOM-002

Given a saved snapshot whose source rotates during upload, when dispatch or cancellation is retried, then original source/window/attempt identities and accounting remain; no replacement history or extra intrusive start is introduced.

## REQ-DOM-003 — Evidence lineage and access

Cases group occurrences; access is projected per artifact. Artifact, lineage edge, managed copy, retained audience, analysis result and privacy decision preserve independent identities and constraints. Lineage is acyclic and inherits the strictest applicable authorization/region/deadline. EvidenceShare contains concrete artifacts/recipients; SharingIntent and publication registrations separately bound future shares. Multiple manager assignments do not replace immutable creator/requester/executor identities.

### SC-DOM-003

Given a case containing artifacts with different audience/deletion limits, when a share or derived analysis is created, then hidden artifacts remain undisclosed and every selected parent constrains the result; changing owner teams cannot reset expiry or creator provenance.

## REQ-DOM-004 — Transactions, liabilities and deletion

Use the persistence specification’s transactional admission, canonical lock order, idempotency, outbox and fences. Capacity and grant reservations precede effects. Preserve uncertain charges/spend and managed-copy obligations across retries, object deletion and restore. Do not use cascade deletion from a workload/CRD/principal to remove evidence liabilities, revocations or replay tombstones. External effects do not occur while holding database locks.

### SC-DOM-004

Given an unknown commit/start or storage-delete failure, when a controller restarts, then original operation identity, reservation and copy liability survive; re-dispatch cannot manufacture a refund or second authorized start.

## REQ-DOM-005 — Privacy-aware types and evolution

Use explicit units, overflow-checked counters, time/clock uncertainty, opaque Kubernetes versions, domain revisions and typed operation unions. Raw/extract/metadata is separate from possible personal/user/credential classification. Store sensitive plans/parameters/manifests behind protected references, not generic SQL JSONB. Add fields through reviewed domain-to-wire mappings; existing conceptual enum names cannot silently alter a published schema.

### SC-DOM-005

Given a proposed new counter, plan field or state, when schema/migration review runs, then its unit, authority, privacy/backup effect and public mapping are declared; ambiguous numeric duration, plaintext evidence row or widening conversion is rejected.
