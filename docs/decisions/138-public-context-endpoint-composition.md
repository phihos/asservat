# ADR-138: compose public context endpoints through one audited backend

Status: accepted for implementation; staged component qualification only.

The browser, MCP and native-file handlers exist as separate components. Ad hoc
mounting can omit native content, use an unaudited constructor, lose the browser
refresh owner, advertise a different operation set, or send unknown API routes
to the console shell. None would satisfy the developer's complete investigation
and local-tool workflow.

Use a concrete C-20 bootstrap composition that constructs one healthy audited
operation owner for browser, MCP and native HTTP preflight, one session handler,
the existing built-console reader and the actual native-content handler. Share
the installed origin/issuer and preserve distinct bearer resource resolvers.
Require the case/progress/download services; the existing capture operation
continues to control whether new collection is advertised. Read-only retained
evidence access remains possible when capture is disabled.

Dispatch through a private exact-path router without path-cleaning redirects,
API-to-HTML fallback, body buffering or a new shared capacity gate. Preserve the
original HTTP request and response writer so each existing handler retains its
authentication, audit, cancellation and delivery-deadline responsibilities.

This changes no public wire, grant, SQL schema, role authority or retention rule.
It does not start a listener or select fixture/provider inputs. Protected runtime
provisioning, supervised services, installed user-journey qualification and Helm
enablement remain separate required work. See the
[composition contract](../architecture/public-context-composition.md).
