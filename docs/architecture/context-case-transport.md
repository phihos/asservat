# Case metadata through browser and MCP

C-20 composes the C-16 [context case service](context-cases.md) through
`ContextCaseOperations`; its sole operation is canonical `get_case({case_id})`.
A case ID from capture progress is navigation, not evidence authority; the
service authorizes the read.

The projection is `Ready` / `ordinary`, verified `pod-status` metadata with
complete artifacts and effective access/deletion dates. Its digest is the
artifact version, not native SHA-256. The handling notice names possible
personal identifiers, network addresses and paths and states that downloaded
copies cannot be recalled. No native filename, file checksum, bytes, storage
key, target locator, invented title or timeline is returned.

The offline investigation schema generator derives the qualified `get_case`
subset; wider canonical branches the service cannot supply are rejected. The
same validated JSON goes to browser and MCP. Missing, foreign, unpublished,
denied and failed results share one nondisclosing unavailable response.

`NewInvestigationOperations` composes the configured capture and case services
and rejects duplicate advertised names. Case-only configuration exposes only
`get_case`. No download operation is registered merely because its schema or
UI exists.

The case's artifact list is paginated with a cursor, never truncated; an MCP
page stays within the 96 KiB tool-result bound ([MCP runtime](mcp-runtime.md)).
Browser reads use exact-origin TLS, session-bound CSRF and POST. MCP uses its
bearer identity. Authorization happens once per operation
([ADR-311](../decisions/311-operation-authority-recheck.md)); ordinary HTTP
timeouts bound I/O. There are no subscriptions, anonymous links or delegated
client credentials.

Native download wiring is in [the evidence wiring map](context-evidence-workflow.md).
