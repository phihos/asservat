# Domain foundation

The [domain guide](../docs/domain/README.md) and [typed catalog](../docs/domain/model.yaml) map these concepts to SQL, CRDs and Go. Wire contracts keep authority over public enums and field shapes.

## Core entities

| Entity | Meaning | Stored as |
| --- | --- | --- |
| Principal | Issuer-scoped human or OAuth client | Identity provider |
| AccessBinding, PermissionSource | Who may do what on which workloads ([permissions](permissions.md)) | Kubernetes |
| DebugPolicy | Recurring detectors plus actions on a workload | Kubernetes |
| Capture | One accepted collection, manual or triggered, with its immutable plan ([execution](execution.md)) | SQL |
| ActionAttempt | One start of one action on one pod, keyed by operation ID | SQL |
| SourceSession | An armed ongoing recorder; snapshots save windows from it ([action lifecycles](action-lifecycle.md)) | Connector, reported to the hub |
| Artifact | One encrypted evidence object with lineage, audience and deadlines ([evidence](evidence.md)) | Object store, SQL catalog |
| Case | Groups occurrences and their artifacts | SQL |
| AccessGrant | Approved expiring authority for intrusive or raw work ([authorization](authorization.md)) | SQL |
| EvidenceShare | Concrete artifacts shared with named recipients | SQL |
| Audit event | One append-only row per security-relevant effect (ADR-330 D6) | SQL |

## REQ-DOM-001 — Identity and authority boundaries

Identity-provider principals, Kubernetes configuration, accepted hub execution, node source state and committed evidence MUST stay separate. Users author by name; the hub records Kubernetes UIDs, issuer-scoped subjects and digests as provenance ([ADR-335](../docs/decisions/335-usable-by-default.md) D4). Domain types, SQL rows, CRD spec/status and protocol DTOs are distinct projections with declared write authority. Values carry explicit units; plans are typed SQL columns or versioned JSONB; evidence and manifests stay in the encrypted object store. No tenant or container permission model.

### SC-DOM-001

Given deletion/recreation of a namespace/workload or a recycled PID, when a previous request/history/grant is reused, then identity validation prevents it from silently targeting the new incarnation.

## REQ-DOM-002 — Capture and source lifecycles

Capture, ActionAttempt, SourceSession and source snapshot are separate. A recording save binds existing sources. A source has its own end, budget and readiness; cancelling or retrying a snapshot neither starts a source nor stops an unrelated recorder. A start with an unknown outcome is resolved by its operation ID ([REQ-FED-002](federation.md#req-fed-002--durable-outbound-work-and-compatibility)).

### SC-DOM-002

Given a saved snapshot whose source rotates during upload, when dispatch or cancellation is retried, then original source/window/attempt identities and accounting remain; no replacement history or extra intrusive start is introduced.

## REQ-DOM-003 — Evidence lineage and access

Access is decided per artifact. Lineage is acyclic and a derived artifact inherits the strictest audience, region and deadline of its parents. A share names concrete artifacts and recipients; a sharing instruction on a capture or policy bounds future shares. Manager teams never replace the immutable creator, requester or executor.

### SC-DOM-003

Given a case containing artifacts with different audience/deletion limits, when a share or derived analysis is created, then hidden artifacts remain undisclosed and every selected parent constrains the result; changing owner teams cannot reset expiry or creator provenance.
