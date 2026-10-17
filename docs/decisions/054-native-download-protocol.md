# ADR-054 — Native download preparation and HTTP resume

Date: 2026-10-10. Status: implementation correction preserving REQ-DLD-003 and the maintainer's native local-tool workflow.

Preparation may need authorized regional manifest reads before file size/checksum are known. Make the complete native metadata group optional during Preparing/early failure and mandatory when ready or completed. Unknown values are omitted, never fabricated. Include the opaque strong ETag in verified preparation metadata so the client needs no extra request before a checked resume. Preparing and terminal states cannot advertise resume.

Use `Range` plus `If-Match` in Asservat clients to fail a mismatched version with 412 and no evidence bytes. The previous specification incorrectly assigned that behavior to `If-Range`: [RFC 9110 section 13.1.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.5) instead requires ignoring Range on mismatch. Retain optional standards-compatible If-Range, including full-response authorization/accounting on fallback. The session's artifact stays immutable. A compliant client distinguishes 200 from 206 and never appends a complete response to a partial file. Existing prototype mismatch-denial tests describe that older prototype, not HTTP conformance.

Single ranges, finite output/read work, current per-batch authority, original deadlines, no-store attachments and no object-store redirects remain unchanged. This adds no service, approval or permission-configuration surface. Public download session/transport composition is still being implemented.

The bounded parser also honors If-None-Match ordering/weak comparison and ignores unknown range units under RFC 9110 sections 13.1.2 and 14.2. A 304 still requires current metadata authority; unknown units cannot bypass full-response accounting. No Last-Modified validator is advertised.
