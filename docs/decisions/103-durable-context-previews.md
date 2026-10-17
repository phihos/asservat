# ADR-103 — Durable manual context previews and accepted retries

Status: implementation decision under the maintainer's continuation authorization.
Qualification and enabled runtime scope are recorded in
[implementation progress](../implementation-progress.md).

The current authority observations last only seconds, while a developer needs
time to review a capture. Keeping those observations as permission for a
five-minute preview would weaken authorization. Expiring the whole draft after
five seconds would make the workflow impractical. An accepted request must also
remain discoverable after a lost response, expired preview or disappearing Pod.

Persist a bounded passive blueprint in PostgreSQL: original actor/client,
service-generated operation identities, exact target incarnation, reviewed
canonical scope, placement, relative retention and audience source references.
It contains no tokens, group assertions, runtime proofs, arbitrary free-text
reason or acquisition authority. A reason can only be referenced through
separately encrypted scope-bound control data. The initial implementation covers
`builtin-pod-status-v1`; it must not masquerade as the broader incident-context
preset.

The blueprint has a fixed lifetime of at most five minutes. Enforce the existing
10-preview limit per human across clients and 1000 per installation atomically.
Expiry removes only planning state; it cannot release evidence reservations or
forget uncertain execution. No preview reserves collection capacity or starts a
sensor. Current facts are reacquired on submission and must reproduce the
reviewed scope and audience without silently selecting a replacement Pod.

Retention review stores relative ages and source pins. Evidence lifetime does
not begin when the preview is created. The first submission preparation supplies
the registration anchor and current effective dates; accepted retries retain
that original registration. Short retention can therefore remain useful after
a longer human review. Assessment freshness remains distinct from preview
lifetime, and an assessment never grants permission to collect.

Before requiring a live preview, look up the authenticated actor/client's
idempotency key using a request digest derived from the immutable preview ID.
An existing operation is returned only after current identity, recovery and
stored-target entitlement checks. The original capture admission transaction
binds the key and creates the operation atomically; no separate request-result
association can be lost between commits. A changed preview under the same key
conflicts. A missing row proceeds through fresh preview validation and ordinary
atomic admission. Unknown commit outcomes never allocate new operation IDs or
start another acquisition merely to recover the response.

This decision does not resolve the separate historical capture-row ceiling
([U13](../reviews/user-task-review.md)), implement the encrypted free-text control
writer, or enable a public investigation route. Those remain required work, as do
execution, publication, progress and native download composition.
