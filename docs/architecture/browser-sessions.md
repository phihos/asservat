# Browser sessions

Scope: C-02 owns session coordination, C-20 the HTTP ingress and C-21 the
OIDC/SQL adapters. This implements REQ-AUT-001, TASK-07 and S-01/S-02 under
[ADR-060](../decisions/060-bounded-browser-sessions.md), ADR-330 and
[ADR-335](../decisions/335-usable-by-default.md) D5. The design
is the standard backend-for-frontend pattern (IETF *OAuth 2.0 for Browser-Based
Applications*, BFF; oauth2-proxy; Grafana server-side sessions). A session
identifies a current human; it never grants target permissions, evidence
disclosure, policy execution or approval authority.

## Login

1. GET `/auth/login?return_to=/investigations` validates a local return path,
   stores a five-minute login row (hashes of state and a browser-binding
   cookie, nonce, PKCE S256 verifier) and redirects to the configured
   authorization endpoint.
2. Only when an administrator configures `approvals.stepUp`, GET
   `/auth/step-up?return_to=/approvals/<id>` starts the same login with the
   configured `acr_values` and `max_age=0`. A successful login does not
   establish approval assurance: each approval checks the returned signed
   `acr`/`auth_time`, current policy and current target permissions. Without
   step-up settings, approvals use the ordinary session and the route is not
   offered. See [ADR-253](../decisions/253-approval-stepup-login.md).
3. The callback requires the configured issuer, exact state and browser
   cookie, deletes the login row in the same transaction that claims it (a
   repeated or concurrent callback cannot exchange again), verifies the ID
   and access tokens, resolves the human through the current identity
   configuration and updates the human's known-principals row (username,
   display name, groups seen; REQ-AUT-001).
4. It creates a session row and sets an opaque random HttpOnly, Secure,
   SameSite=Lax cookie. SQL stores the cookie hash, subject, issuer, client,
   provider session ID, authentication time, the maximum and inactivity deadlines, a
   CSRF token and the refresh/access tokens encrypted with the application
   session key (AES-GCM, session ID as associated data). The session key comes
   from a mounted Secret; a key ID per row allows rotation, and no KMS call is
   on the request path. A session ends at the earlier of its maximum
   lifetime (default 7 days, configurable up to 30 days) from creation and
   its inactivity timeout (default 24 hours) after the last authenticated
   request; use slides the inactivity deadline (written at most once per
   minute; it rotates no credential), never the maximum.
5. There is no installation-wide or per-user session cap; rows are small,
   login is bounded by the ingress rate limit and idle sessions end at their
   inactivity timeout. Login and logout write an audit row in the same
   transaction (ADR-330 D6).

`GET /api/v1/session` returns the subject, username, CSRF token, expiry
and, when configured, the `step_up` state. A returning tab calls `GET /auth/csrf` and then
`POST /auth/refresh` with that token and an exact `Origin`. State-changing
requests require the CSRF token and exact `Origin`.

All routes require HTTPS. The handler trusts no forwarded headers unless a
separately configured ingress boundary terminates TLS. Responses disable
caching, framing and referrers. Provider tokens, client secrets and upstream
error bodies never reach the browser. The
[authentication OpenAPI](../interfaces/browser-auth-openapi.yaml) is separate
from business-operation/MCP parity because redirects and provider callbacks are
protocol endpoints.

## Use and refresh

A request resolves its session once and authorizes the operation once
(ADR-311); the resulting identity is reused for at most
`identity.AuthorityRecheckInterval` and never past the session deadline or
access-token expiry. Group membership comes entirely from the current access
token.

The server refreshes the provider tokens only when the access token expires
within 60 seconds at the time of use, so group membership follows the
provider while the user works. Rotation is optimistic: the update
succeeds only if the row's credential version is unchanged; a concurrent
request that loses the race re-reads the row and uses the new tokens. The
provider's refresh-token reuse detection covers replay. If the provider call
fails or its reply is lost, the request fails; the next request retries with
the stored token, and a provider-revoked token or an expired provider
refresh token requires a new login. A refresh never extends the maximum
lifetime. The new tokens must keep the
subject, client, provider session and original authentication time.

## Logout

`POST /auth/logout` validates CSRF and `Origin` and deletes the session row.
The UI claims sign-out only after a successful response; an unknown outcome
offers retry. This signs out of Asservat, not every service using the identity
provider.

OIDC back-channel logout tokens are validated for issuer, audience, signature,
expiry, recent issue time, event ID, logout event and subject/session binding,
with `nonce` forbidden. The handler deletes the matching sessions and stores
the event ID for 25 hours so a delayed duplicate cannot be replayed.

## Settings

Under [ADR-061](../decisions/061-current-browser-configuration.md) the hub reads
`browser.json` from a mounted ConfigMap. The
[example](../../examples/browser-settings.json) and
[schema](../../specs/contracts/browser-settings.schema.json) contain issuer,
client, exact HTTPS origin (no path, userinfo, query or fragment; lowercase
host; default port omitted), the maximum lifetime and the inactivity timeout,
never credentials. The process validates the file at startup and on change and keeps
the last valid settings until a new valid file replaces them; an invalid file
is logged and ignored. Sessions whose issuer or client differs from the
current settings are rejected. Lowering the maximum lifetime clamps existing
session deadlines (from their creation times) with one SQL update when the
new settings load; raising it affects only new sessions.

## Persistence

Migration 00020 provides `browser_login`, `browser_session` and
`browser_logout`. Rows are bounded (256 KiB ciphertext per session).
Concurrent operations lock only the affected session row; there is no shared
root row. The browser role has no evidence or capture privileges.

Expired login, session and logout rows have no event source, so the hub worker
deletes them in batches of at most 256 rows on a timer set to the earliest
expiry from an index, at most once per minute.

## Verification

`make identity-integration` runs the handler against owned Keycloak and
PostgreSQL fixtures: code/PKCE/nonce exchange, session creation, concurrent
refresh, group removal, local and back-channel logout and cleanup. Results are
recorded in [implementation progress](../implementation-progress.md).
