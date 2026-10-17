# ADR-134: Explicit continuation of an accepted capture

Status: accepted for implementation; installed qualification remains required.

The first bounded API pod-status submission may commit admission before intent
audit or acquisition finishes. Historical request replay, resolution and progress
must remain passive. Reusing an expired request identity or silently acquiring
from polling would violate that boundary.

Add optional `continue_acquisition: true` only to the existing
`request_capture` preview/key branch. Browser and MCP use the same schema and
service. Omission keeps passive accepted replay; false and the expanded request
branch with this field are rejected. Browser requests retain their exact matching
Idempotency-Key header. Collection enablement and capture entitlement still apply.
The Accepted response is unchanged and promises no collected or published evidence.

The action looks up the exact accepted actor/client, preview and original key;
it cannot admit a missing request, allocate another identity, recreate a preview
or select another Pod. A fresh request-owned identity and current recovery bound
the call to at most five seconds. Every subsequently known shorter bound is
retained through blocking work. Exact acknowledged original intent precedes the
existing runner, which rechecks original executor, current permission, capability,
Pod/process, retention and recovery. Original registration and execution/start
intervals never change. An already acknowledged audit may be read after its
writer interval; an unresolved writer cannot receive another permit from this
action. The audit port remains provider-neutral.

Only the positively acknowledged first SQL execution-preparation winner may
generate wrapping keys. A prepared row returned without that winner indication
is uncertain and cannot prepare again. Started or stored rows remain passive.
This preserves the one-attempt boundary and makes continuation useful before
execution preparation; it does not recover a spent or unknown key attempt.

The console offers an explicit Continue collection action for currently observed
Pending work only while it retains the original receipt. Polling, session refresh,
reload and pasted capture URLs never invoke it. Unknown responses preserve the
receipt and same key. A known closed or uncertain preparation stops further
continuation and directs the user to check the original result before deliberately
starting another investigation. Starting another investigation does not cancel the
original. No automatic replacement, extra approval or acquisition queue is added.

Component tests use synthetic authority ports and actual request-owned identity
handles. Native fixture source composes separate SQL roles, real API acquisition
and encrypted storage; only an executed, source-matched native report qualifies
that composition. Installed regional dispatch, intent lifecycle and complete public
composition remain prerequisites; public collection stays disabled.
