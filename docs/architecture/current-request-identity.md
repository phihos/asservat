# Current identity across browser and MCP operations

C-02 supplies one request-owned identity handle to C-03's authorization
services. Browser sessions and MCP bearer credentials use the same policy
evaluator. The handle identifies the caller for one operation; it is not a
collection, publication or disclosure permit.

## Ingress

- `identity.NewBearerRequest` verifies the bearer credential through the
  installation's resolver. The MCP transport pins the resource audience, issuer
  and client policy in that resolver; the request cannot choose them.
- `identity.NewBrowserRequest` resolves the server-side session cookie. The
  browser transport checks origin and, for a command, CSRF before resolution
  (`SessionHandler.AuthenticateCurrent`). Only this ingress step may rotate the
  session's provider credentials.
- Provider tokens never enter a browser response or the application handoff.

Each constructor authenticates once and returns `CurrentIdentity` with the
resolved principal, client, scopes, stable group IDs and policy revision.

## Lifetime

The handle is valid until the earliest of:

- the token, session or group-assertion expiry;
- ingress time plus `identity.AuthorityRecheckInterval` (30 s, ADR-311);
- the operation's own original deadline;
- cancellation of the original request.

Consumers use the handle as resolved; they do not re-read identity after
blocking work. An operation that outlives the handle (a selected `Within`
window for evidence reads or grouped capture requests) authenticates again
at its next public request, never by renewing the handle. A later
observation can only shorten the handle. The handle keeps the original
request's cancellation even when a consumer supplies `context.Background`.

Session revocation, logout and identity-policy changes reach later requests
through the session store and the identity-policy cache (see
[identity eligibility](identity-eligibility.md)). A started download response
continues under ADR-312's original bounds.

## Consumers

`Evaluator.EligibilityCurrent`, `Evaluator.ContextEligibilityCurrent` and
`ContextDownloadAuthority.CheckDownloadCurrent` consume the handle and evaluate
permissions once per operation. Target denies, retained audiences, retention
deadlines and SQL effect checks at commit remain required. No transport gains
an alternative policy engine.

The handle belongs to one finite operation. It is never stored with a capture,
passed to a worker or reused by a later request. Production transports build
handles from the configured services; no user input selects an implementation.
Test fakes implement the ports only inside tests.
