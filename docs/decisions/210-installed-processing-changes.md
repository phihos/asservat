# ADR-210 — Installed processing changes by a privacy operator

Date: 2026-10-20. Status: proposed; implementation in progress.
Requirements: REQ-CAP-005, REQ-EXE-002, S-02; ADR-127, ADR-146, ADR-192, ADR-194.

## Context

ADR-127 requires a current privacy operator to initialize processing explicitly
before the first capture, while the catalog is empty, and later to restrict or
release it. ADR-146 makes every preview and admission check processing coverage;
`processingRootValid` requires `initialized_at`. The installer already writes
the operators (`Public.ProcessingOperators`) into the capacity processing source
and the owner download environment (ADR-192/194).

No installed path performs a processing change. Only component fixtures call
`privacy.ProcessingChanges.Change` directly. Local journey hold 11 showed
`processing_root.initialized_at` NULL and every preview refused at
`processing/read/root-invalid`. Hold 13 marked the root initialized by direct
fixture SQL (an experiment, not a product path) and previews then reached the
coverage verdict.

## Decision

1. The hub-api serves `POST /api/v1/processing/changes` on the browser origin,
   modelled on the ADR-193 fleet route: session, CSRF, exact JSON media, one
   request per principal and two in total. The `Idempotency-Key` header is the
   change's `RequestID` (a UUID), so a retry resumes the same audited change.
   The body carries the change's action and, for rules, its rule ID, expected
   revision and scope. The reply is the processing receipt.
2. The route calls the existing `privacy.ProcessingChanges.Change` with the
   request's current identity. Operator membership, recovery, original
   five-second bounds, encrypted audit and SQL serialization stay as they are;
   the route adds no evaluator. MCP gets no processing tool: operators are bound
   to a configured client, and the installed operator client is the console.
3. `initialize_processing` and `restrict_processing` use the normal audit lane
   through the existing selected auditor. Its policy and retained seconds come
   from the current capacity audit profiles for each call, so a profile renewal
   never binds a stale policy. `release_processing` needs the separate
   processing release lane; until that lane is composed the route answers 503
   for it, and no release is possible.
4. A new hub SQL purpose, `processing-decision`, holds exactly the grants of the
   component fixture role `processing_decision_runtime`. This changes the public
   runtime role layout digest; existing installations provision it with the
   next layout.
5. Decisions bind the policy to `processing_root.source_uid`, the capacity
   processing source. The hub-api reads that source through its own guard, with
   the owner account's denied dry-run probe added to the owner's guarded
   sources. The owner download environment remains the download path's policy.

6. Console login itself had no installed producer: nothing projected the
   protected browser settings into SQL, so `browser_session_root` never
   existed and every login was denied (ADR-184 lists the hub-worker's
   browser-settings role as an open gap; local hold 18). The hub-worker's
   permission projection gains a browser section: the existing
   `browser-settings` login and the existing ADR-061 observer, which reads the
   settings ConfigMap by name and UID once per second and fences the
   projection when a read fails. The hub-worker's Role gets `get` on exactly
   that ConfigMap. Browser session cleanup (`browser-cleanup`) stays an open
   gap; expired logins and sessions are only pruned on new logins.

## Consequences

The installed journey adds a step in which the configured operator initializes
processing through the console route before the first preview. The journey's
operator entry must match an identity the fixture's Keycloak issues.

Coverage also needs a capture's deletion date before the processing root's
current end. Root renewal sets that end `AdmissionSeconds` ahead (at most one
day) and runs only in the last ten seconds, so a capture whose retention plus
deletion budget exceeds the remaining interval is refused as known insufficient
coverage. The journey profile uses the one-day maximum. Longer retention cannot
be covered by this design; that limit is recorded, not changed here.
