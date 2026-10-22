# ADR-171 — Hub-run context execution with delegated regional operations

Date: 2026-10-14. Status: accepted; implemented, and the native public journey passes on this path.
Requirements: REQ-FED-001/002, S-02 context collection; TASK-03 / TASK-11.

[ADR-216](216-request-owned-context-start-observation.md) refines the repeated
hub checks below: one start reuses one complete observation within its original
interval, with current SQL effect checks. Qualification is tracked separately.

## Context

ADR-135 runs `APIContextRunner` in the regional process after the hub signs
and routes one API context work. That runner reads and writes hub SQL: the
accepted work, execution preparation, start binding, start/outcome records,
permissions (eligibility), retention, capability and recovery. The region also
authenticates hub owners and discovers them through hub SQL. These assumptions
predate [ADR-168](168-rotating-cluster-enrollment-credential.md)'s
outbound-only connectivity. They conflict with
[ADR-169](169-delegated-regional-lifecycle-channel.md)/[170](170-federation-compartment.md)
and with the role inventory: connectors and collectors hold no hub SQL
credential, and encrypt and upload under wrap-only and write-only scopes.

Delegating each SQL port to the hub while the runner stays regional was
rejected. The hub would then perform effects from an `APIExecutionCheck`
assembled in the region. A compromised regional process could present a check
claiming eligibility it never had. The hub would have to recompute every
authority input anyway.

## Decision

1. The hub runs the unchanged `APIContextRunner` within the original
   request. All authority and SQL ports are hub-local: accepted work, execution
   journal, eligibility from current permissions, capability, retention and
   recovery, all under the human's own current identity. The region no longer
   asks identity questions.
2. Only cluster-local ports are regional operations. Each is one request and
   one reply on the existing outbound context-start exchange:
   - `ResolvePod`: target resolution.
   - `ReadAPIProcess`: process proof.
   - `PrepareStart`, `ReadyStart` and `ConsumeStart`: the local start CAS and
     journal.
   - `PrepareOutput`, `AcquireContext` and `CompleteStored`: evidence output.
3. Plaintext evidence and data keys never leave the region. `PrepareOutput`
   prepares framed encryption with the regional wrap-only key sealer and keeps
   the handle in the regional process. `AcquireContext` performs capture,
   validation, encryption and the four write-only uploads in the region within
   the committed start's original deadline. It returns only the acquisition
   instant and copy receipts. `CompleteStored` returns the writer completion
   facts. The runner uses this combined path when the prepared output
   implements it, instead of a local `Collector.Capture` plus `StoreContext`.
4. The hub still sends the signed work first. The region verifies it with its
   verify-only trust and the current receiver check. It then answers operations
   only for that exact work, in the runner's fixed order, each bounded by that
   work's and the request's original deadlines. A region never executes an
   operation without a verified work for the same capture and channel.
5. Regional observations (process, target, start dispositions, copy receipts)
   are delegated regional proof, as in ADR-169. Every effect stays where its
   data lives: SQL effects on the hub, cluster effects in the region.
   Publication still requires the independent verification, audit and catalog
   path over the stored ciphertext.

## Consequences

The regional process needs only Kubernetes credentials, write-only object
credentials for its evidence store and a wrap-only key credential. It holds no
SQL or unwrap authority. Hub owner discovery and authentication for the
outbound exchange move to the federation endpoint (an ADR-169 purpose), so the
region needs no SQL for them either.

Frame bounds change: the identity frames disappear, and up to about fourteen
operation pairs replace them. Existing work/result/receipt framing, the
transport observation lease (ADR-163), standby residency, per-cluster budgets
and every original five-second authority interval remain.

## Implementation

- `contracts`: operation request/response frames, at most 16 operations of
  32 KiB each, 36 frames per exchange.
- `transport/contextstart/operations.go`:
  - `HubOperations` implements the runner's cluster-local ports by remote calls.
    Its `Capture` and `StoreContext` refuse, so native bytes cannot reach the
    hub.
  - The region's `regionalSession` binds every operation to the verified work:
    capture, attempt, cluster, Pod and plan scope digest, the expectation digest
    and the resolved pin. (The work's budget digest is the capture budget, a
    different value from the execution binding's, and is not compared.) Acquisition requires the committed start, and
    a second consume is refused.
  - Failure labels are closed. A failed store still returns its acquisition
    instant.
- Frame lease: added operation request/response transitions.
- Router: `Attachment.Run`.
- `execution.APIContextRunner`: uses `evidence.ContextAcquirer` when the
  prepared output implements it.
- `bootstrap.RegionalAPIContextStart`: runs the runner on the hub. The public
  assembly accepts only hub ports.
- `ServeRegionalAPIContextExchange` and `RegionalContextStartConnections`:
  serve a `contextstart.RegionalLocal`.

Verification so far:
- `TestContextStartActualHTTP2HubRunOperations` passes over actual TLS 1.3/h2.
  It covers a foreign-capture start refusal, acquisition before the committed
  start, and hub `StoreContext` refusal; only copy receipts cross.
- `TestAPIContextRunnerAcquiringOutputCapturesAtTheOutput` passes, including
  spent capture and store failures.

The legacy identity-question mode is removed. Frame kinds 3 and 4 are retired
and always rejected; the identity DTOs, `Attachment.Dispatch`,
`ServeHub`/`ServeRegional` and `AuthenticatedAPIContextRunner` are gone. Their
transport properties (EOF, cancellation and late-reply rejection joined with a
blocked operation, frame order and per-exchange frame budget) now run against
the operation frames, over actual TLS 1.3/h2 in `adapters/mtls`. Diagnostic
stage labels are `hub-operations` and `regional-operations`.

Native: [the public journey run 2](../../test/results/adr171-journey-2/result.json)
passes on this path (exit 0, no validation errors). It covers preview, request,
hub-run execution with regional capture, encryption and upload, publication,
case, native download with continuation, Stop and revocation, all against real
PostgreSQL, Kubernetes, S3 and TLS. The first request took 4.285 s, the same as
the three earlier passes (4.27–4.28 s).
[Run 1](../../test/results/adr171-journey-1/result.json) failed and is
retained: the regional binding check also compared the work's capture budget
digest with the execution binding's, which is a different value, so every start
was refused. Capture, attempt, cluster, Pod and plan scope now bind exactly.

## Remaining

Delegated owner discovery/authentication over federation
([ADR-172](172-delegated-owner-discovery.md)) and composing the product regional
process with its local ports, write-only evidence store and wrap-only key
credentials.
