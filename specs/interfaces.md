# Public interface design

The [interface inventory](../docs/interfaces/README.md), [OpenAPI](../docs/interfaces/browser-openapi.yaml), [operation registry](../docs/interfaces/operations.yaml) and [MCP workflow guide](../docs/interfaces/mcp-workflows.md) describe the outward boundaries.

## REQ-INT-001 — Shared domain behavior and explicit transports

Browser and MCP MUST call the same application services through one assembly; shared operations reuse the canonical MCP input/output schemas. Human review and operator operations have their own contracts. HTML routes, OAuth, Kubernetes, Alertmanager, CloudEvents, health/metrics and connector interfaces are documented with audience, versioning and trust boundary. There is no generic shell, SQL or Kubernetes proxy. Native downloads are authenticated ([artifact downloads](artifact-downloads.md)); anonymous or bearer-only file access is prohibited.

### SC-INT-001

Given equivalent browser and MCP requests, when current scope/permissions/limits are equal, then plan, assessment, evidence projection and domain error behavior agree; no adapter bypasses approval or capacity.

## REQ-INT-002 — Configuration and human authority

Permission, retention and budget configuration is written only through Kubernetes; browser drafts and previews create no second authority. Maintainer submissions are limited to reviewed configuration kinds. Review decisions need an independent human ([authorization](authorization.md)); no MCP tool approves.

### SC-INT-002

Given a permission editor draft or an agent attempting review, when it submits through the browser/MCP boundary, then unsupported configuration mutation or agent approval is rejected; a permitted maintainer change still faces Kubernetes conflict and execution acceptance checks.

## REQ-INT-003 — Bounded errors, retries and asynchronous work

This requirement owns the public API conventions; other specs link here.

- Lists are paginated with authenticated cursors or streamed; any byte or time limit states its reason.
- Mutations take an idempotency key and the expected revision. A retry with the same key returns the original operation; a different body under the same key conflicts.
- Each operation is authorized once and the decision reused for at most `identity.AuthorityRecheckInterval` (30 s) and never past its original deadline ([ADR-311](../docs/decisions/311-operation-authority-recheck.md)).
- Status reads wait server-side for the next change (at most 30 s, ADR-330 D1); the console gets the same changes over its Server-Sent Events stream. Status reads are never charged.
- Errors are safe problem details with stable domain codes; MCP keeps its result envelope. Before visibility is established, responses reveal no existence.

### SC-INT-003

Given a command accepted before connection loss, when browser or agent retries with the same key, then it receives the original bounded operation. A revoked share fails within 30 s, and error output contains no evidence or hidden resource details.

## REQ-INT-004 — External integration minimization

Incoming alerts authenticate the configured receiver, validate standard payloads and deduplicate by episode and transition. Outgoing events carry only allowlisted identifiers and authenticated references with stable retry identities. Metrics and probes have bounded cardinality and leak no evidence or identity. No capture names an arbitrary notification destination.

### SC-INT-004

Given duplicate/reordered alerts and an artifact containing a credential-like string, when collection and event delivery run, then duplicate input does not create an extra action and notification/metrics fields never contain the artifact string.

## REQ-INT-005 — Compatible evolution and agent ergonomics

MCP keeps stable tool names, typed schemas, bounded results, explicit version negotiation and schema parity with the browser. Results explain missing evidence, coverage and next actions. Handoff references carry no authority. Evidence is untrusted data; its instructions are never followed. Profile versions are pinned; unknown outcomes are reported, not widened to defaults.

### SC-INT-005

Given an agent reading partial evidence or repeating a recording save, when the response is generated, then it can identify missing coverage and the correct next tool without interpreting a free-form command; an expired source requires fresh selection, not an expanded capture.
