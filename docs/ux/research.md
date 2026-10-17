# UX and interface research

Checked 2026-10-09. These primary sources inform the design; they do not certify the prototype or prove a deployed implementation.

- WCAG 2.2 adds relevant AA criteria for unobscured focus, target size, redundant entry and accessible authentication. The normative target-size minimum includes exceptions; this design chooses larger 44px principal controls as a usability choice. Reflow, keyboard and contrast require separate evaluation. [W3C summary](https://www.w3.org/WAI/standards-guidelines/wcag/new-in-22/).
- Modal dialogs need an accessible name, contained keyboard focus, an accessible closing path and sensible focus restoration. The prototype uses native dialog behavior and explicit opener handling. [WAI dialog pattern](https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/).
- MCP tool definitions support strict schemas and structured results; stable ordering helps discovery/caching. Tool annotations describe behavior but cannot enforce trust or authorization. The catalog remains the shared transport-level source. [MCP tools specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools).
- OpenAPI 3.1.1 provides a suitable JSON Schema-compatible description for the browser boundary and reuse of existing schema references. It is a selected contract version, not a claim to use the latest OpenAPI release. [OpenAPI 3.1.1](https://spec.openapis.org/oas/v3.1.1.html).
- HTTP problem details give transport/console errors a conventional machine-readable envelope. Safe extensions carry request ID, domain code and next action; evidence and secrets are excluded. Shared MCP operations retain their established result envelope rather than silently changing error semantics. [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457.html).
- Kubernetes resourceVersion is an opaque concurrency token; API clients must respect version/conflict semantics. The design separates it from SQL row revisions and avoids a second configuration writer. [Kubernetes API concepts](https://kubernetes.io/docs/reference/using-api/api-concepts/#resource-versions).

The screen organization, terminology, explicit lifecycle separation, profile composition and actor-specific starting pages are design inferences from the accepted product constraints. No external source establishes that Asservat is easy to use. Participant task studies and supported-browser/assistive-technology tests remain release work.

The subsequent [web GUI review](web-design-research.md) researches visual hierarchy, navigation, tables, disclosure, responsive interaction and the applied minimalist overhaul. It preserves these protocol and application-boundary decisions.
