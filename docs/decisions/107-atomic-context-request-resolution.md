# ADR-107 — Atomic resolution of an uncertain manual capture request

Status: implementation decision under the maintainer's continuation authorization.
Native qualification and public enablement remain in implementation progress;
the initial change is staged outside the live repository while the preceding
snapshot is verified.

A lost capture response must not make a developer repeat production collection
accidentally. An ordinary request error cannot prove non-admission: another
request may commit after the first read-only replay lookup. Closing a browser
editor also cannot fence a plan already held by another request.

Add the explicit mutating `resolve_capture_request` operation. It returns the
original accepted capture, or atomically closes this actor/client's original
preview so it cannot be admitted afterward. It never starts collection, cancels
an accepted capture, or claims that no other captures exist. Unknown COMMIT,
current authorization failure and expired response authority stay unresolved.
Clients retain the original receipt and never automatically substitute a fresh
preview or idempotency key.

Migration 00036 adds an immutable preview ID to new reviewed admissions, a
first-close marker on passive previews, and bounded actor/client-scoped negative
fences for missing previews. Preview creation, reviewed admission and closure
share the existing permission-root serialization point. Accepted lookup always
precedes closure. A closed unexpired preview remains present so an uncertain
create retry cannot reopen it. An original expired create is rejected against
current SQL time; missing-row fences last at most five minutes, do not renew,
and count against the existing ten-per-human and 1,000-per-root preview budgets.
Capacity exhaustion is unresolved, never proof of non-admission.

Historical rows with no preview ID are checked using their exact submission
digest and independently decoded canonical executor scope. Ambiguous or invalid
legacy matches remain unavailable. This preserves accepted-first behavior for
an earlier preview submitted under another key without inventing a preview ID
from a hash.

Resolution needs current `evidence:read` scope and the exact original actor and
client. Accepted metadata requires current ordinary target read entitlement;
losing capture scope alone need not prevent recovery. Closing one's own passive
preview returns no target metadata and reduces authority, so losing target
entitlement does not prevent that negative operation. An inaccessible accepted
capture cannot be reported closed. Another actor's preview ID cannot affect the
original preview or return its receipt. Recovery and original final response
bounds remain mandatory. Acquisition disablement or a missing Pod does not
prevent request resolution.

C09 requires a named reviewed-admission port whose SQL transaction validates the
exact persisted blueprint. The earlier lower-level admission port does not
satisfy this public coordinator's dependency. Neither a browser field nor an
optional boolean can skip the durable review check. The resolver uses its own
SQL credential with close/fence writes only; it cannot insert a capture, change
custody charges or rewrite preview identities/deadlines.

This change does not solve U13's permanent historical capture ceiling. Backed
per-workload control-metadata capacity and dependency-aware finite retirement
remain separate work. Closing a passive preview never releases evidence storage,
execution spend or retained audit obligations.

See [context request resolution](../architecture/context-request-resolution.md)
for the component boundary and measured scope.
