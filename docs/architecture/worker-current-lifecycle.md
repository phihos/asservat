# Request-owned identity through worker dispatch and enrollment

This C-14 implementation connects the existing dispatch/enrollment components to the browser/MCP `CurrentIdentity` port under REQ-DLD-002/003 and TASK-11. It refines [worker dispatch](download-worker-dispatch.md), [credential enrollment](worker-enrollment.md), [request routing](worker-request-routing.md) and [shared owner locators](worker-owner-locator.md). It changes no public schema, private protocol, SQL table, certificate layout or approval scope.

## Typed hub entry points

`DownloadDispatcher.EnsureCurrent`, `WorkerEnrollmentCoordinator.EnrollCurrent` and `NewCurrentWorkerEnrollmentOperation` accept the actual request-owned identity from the configured ingress. They call the existing current download authorizer. The string-credential entry points remain compatible for existing callers; the typed path does not call them or synthesize a token.

The hub holds one private authority observation for the operation. Construction
checks the request identity and required scopes, obtains one complete download
authorization, and pins its exact scope and earliest original
identity/request/authority deadline, capped at five seconds. Later `Check` calls
validate that retained observation locally: scope, expiry, clock direction and
owning-request cancellation. They do not repeat identity, permission, catalog or
retention reads. Independently read source/attachment bounds may shorten the
operation; nothing can restore or renew its deadline. Passing `Background`
internally cannot detach a check from its owning request's cancellation.

The native runtime passes the constructor's first authority observation directly
to its immediately following attachment read. Only local validation and deadline
narrowing intervene. Before that read, the observation is checked again for
scope, current environment/profile, cancellation, clock rollback and the earliest
original source/request cutoff. Dispatch and later attachment reads use the same
request-owned observation. The installed prepare coordinator supplies its initial
checked authority through a private native handoff and consumes it for the final
view too. The complete finite Preparing path therefore performs one full authority
construction. Ready metadata uses the same private short-proof handoff while
retaining its independent current SQL observations. Standalone runtime calls and
each new public operation obtain fresh authority. Final identity comparison,
exact scope, original deadlines and current SQL effects are unchanged.

Dispatch retains the observation through reserve, encrypted intent
audit/acknowledgement, create claim, exact create-or-lookup, observed Job
registration, Pod binding and final registry read. Enrollment retains it around
Pod proof, immutable key claim, audit, signing spend, provider result storage,
certificate audit and activation. Current SQL checks still reject permission
revision/suspension, retention/effective-date, processing and recovery changes,
as well as invalid worker generations or spend. Those transaction checks are
independent of the retained observation. Source/configuration and Pod proofs keep
their existing checks and original bounds. Read/provider completion never resets
an interval.

The constructor, local router, shared locator and final certificate delivery use
the same observation. They do not authorize again at each hop. Expiry or
cancellation after blocking work denies the next effect or response. External
identity/group changes need not be rediscovered within the same at-most-five-second
operation; the next operation authorizes again. This bounded handling follows the
maintainer's timing clarification and supersedes the earlier per-helper refresh
choice. A known exact locator claim that became too long is closed; uncertain
claims remain accounted. The registry counts registering and closing work until
it finishes. Certificate response ownership remains live until `Close`, including
original cancellation and any independently shortened response deadline.

## Continuation and boundary

Normal worker startup may exceed one observation interval. A later live request can attach to the same admitted session/worker using the original business key and current authority. A lost Job-create response still permits only exact lookup; no new Job, signing slot, deadline or quota is inferred from a timeout. The request-owned closure is not persisted and cannot be reconstructed from a worker certificate or SQL locator after process/request loss.

The existing worker/owner channels remain **certificate enrollment only**. The Pod supplies its dedicated projected token and identity-free CSR; the hub retains personal authentication. No cookie, provider token, identity claims or `CurrentIdentity` implementation crosses that wire. No native metadata or payload is inserted into certificate relays.

The credential-phase worker executable, protected runtime/environment/allocation producers and an authenticated exact-operation native exchange still need composition. This change does not mount prepare/get/cancel download tools, enable a production native runtime, claim in-Pod native delivery or complete S-01/S-02. The later native exchange needs its own reviewed protocol; it must preserve the existing regional result owner, generation/spend accounting, final disclosure checks and joined cancellation.

## Verification

The paragraphs below record the earlier, more frequent checking contract.
Its immediate external-identity-change cases are superseded by ADR-214's
request-owned observation refinement. Current tests must instead prove one full
worker authorization, bounded reuse, new-operation reauthorization and unchanged
SQL effect checks, expiry, cancellation and conservative accounting. Qualification
of that refinement is tracked in [implementation progress](../implementation-progress.md).

The sparse-stage evidence race suite passed. Tests use the actual `NewBrowserRequest` with an explicitly synthetic session store and a trap on legacy bearer authorization. They cover changed groups/scopes/policy or expiry after blocking calls, one original check across constructor/router/locator/delivery, conservative lost-create recovery, ownership cancellation, mutation of both original claim slices, concurrent out-of-order shortening, proof crossing the original deadline and shorter effect/response contexts. The shorter-context regression failed for both dispatch audit and enrollment claim before the fix. A separate baseline test fails against unchanged source because the typed lifecycle entry points are absent; it passes with this implementation.

The integration source adds `download-worker-enrollment-current-request` to the existing custody fixture. It composes real current authorization, SQL roles/locks, encrypted S3 audit and TLS/process-key certificate enrollment. An actual SQL read waits beyond the original browser-request deadline; the old operation cannot restart, while a separate current request can attach to the same worker. Session storage, Job/Pod proof and issuer are explicitly synthetic. The parent-controlled native run passed all 15 selected worker cases in 32.355 seconds, with 882 unchanged source hashes and complete cleanup; the terminal report is recorded in [implementation progress](../implementation-progress.md). It is not real SSO, in-Pod startup or OpenBao qualification. The stronger in-Pod continuation/native-transfer scenario remains pending.

Exact commands, logs, source/base hashes and qualification limits accompany the staged handoff. Repository-wide and external fixture results belong in [implementation progress](../implementation-progress.md) after they actually run.
