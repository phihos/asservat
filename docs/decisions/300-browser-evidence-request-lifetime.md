# ADR-300 — Keep browser observations separate from request lifetime

Date: 2026-11-04. Status: selected engineering correction; installed qualification pending.
Requirements: REQ-AUT-001, REQ-INT-001/003, REQ-PRF-003; S-05.

## Observed problem

The installed accepted-heavy comparison in native41846328376 completed through
MCP in10.502s, with a joined worker under384MiB/500m. The equivalent React
comparison received only4.679s for its original request, and3.330s for the native
operation, then failed at `until-request`. The public handler already selects
the existing twenty-second evidence-read window (ADR-291).

Two internal handoffs reduced every real browser identity to at most five seconds:
credential-refresh scheduling metadata, and the current SQL browser-settings
observation. Earlier request-window tests supplied a long-lived fake session and
missed both composed paths. This revises ADR-061's agent-authored coupling between
settings-observation freshness and the entire subsequent identity/request lifetime;
it does not introduce a new maintainer requirement for delayed revocation.

## Decision

Keep the original five-second settings projection and all current-settings checks.
Every SQL session read must validate the pinned root, epoch, issuer/client/origin,
settings freshness and session state before and after blocking work. Suspension,
stale settings, revocation, replacement and invalid bindings still deny that read.
A successful observation is not renewed or reused after its original deadline.

The returned request identity keeps its independently verified token, signing-key,
group and identity-policy cutoffs and the actual current session expiry. The
current-request owner additionally fixes the operation-specific caller window at
construction: twenty seconds for evidence reads, five seconds for ordinary
operations, with all earlier caller/identity/session cutoffs retained. Later
checks cannot extend the original owner or silently change principal, groups,
scopes or policy. Every later session resolution and final disclosure check still
requires current persisted settings and session state. Reads never refresh
credentials after initial ingress.

The five-second `CredentialWindow` is refresh-scheduling metadata, not a second
identity expiry. Validate it when used for scheduling without replacing the
verified identity's independent deadline. Login callback creation retains its
existing original settings handoff; CSRF-only paths return no identity. Fixed
session expiry, monotonic lifetime shortening and epoch/logout rules are unchanged.

An in-flight analysis may outlive its initial settings observation inside the
original twenty-second request. The initial observation cannot authorize its
later disclosure: current identity/session checks must succeed again. This is
bounded current-state enforcement, not instantaneous interruption at every
configuration change or byte. Cancellation and final socket deadlines remain
linked to the original request. A lost or failed outcome remains spent and is
never replayed or refunded merely because a new session check succeeds.

## Cost and verification

The observed failure blocks an ordinary supported browser workflow, not only an
adversarial test. The smaller correction separates existing lifetimes rather
than adding a request revalidation loop. Added API/SQL reads, watches, services,
permissions, credentials, state machines, configuration and migrations:0. The
existing settings observer and its one-second loop are unchanged. No retention,
raw approval, processing, worker or native-source limit changes.

The composed regression uses the real identity service and browser-session
application over existing synthetic store/crypto ports. It reproduces both caps
independently, then exercises six seconds of injected-clock work under the
original twenty-second owner. Fresh current settings are required for the later
read; stale/revoked/invalid settings, shorter token/key/policy/session/caller
bounds, changed membership and cancellation still deny. This is component proof,
not installed identity or elapsed browser qualification. Run the owned real
identity fixture and the exact installed browser comparison before claiming that
end-to-end outcome. Preserve original failed reports and cleanup evidence.
