# Current identity across browser and MCP operations

C-02 now supplies one request-owned current-identity handoff for C-03's existing
authorization services. Browser sessions and MCP bearer credentials use the same
policy evaluator. This is a finite identity observation, not a collection,
publication or disclosure permit, and it introduces no public schema or migration.

`identity.NewBearerRequest` verifies the credential through the installation's
configured resolver. The MCP transport must still pin the intended resource,
issuer and client policy in that resolver; this constructor does not establish
an audience from the request. `identity.NewBrowserRequest` resolves the private
server-side session cookie. Its caller must already have checked the browser
origin and, for a command, CSRF. The browser transport exposes this composition
through `SessionHandler.AuthenticateCurrent`.

Each constructor returns `CurrentIdentity` and a defensive initial observation.
The observation supports principal accounting, presentation and the original
deadline. Application authorization uses `ResolveIdentity`, which reads the
current identity again; passing the initial struct alone is insufficient.
The handle keeps the original request's cancellation even if a consumer supplies
`context.Background`, and links both contexts while a dependency blocks.

The original interval ends at the earlier of initial identity validity and five
seconds from construction start. A browser session's expiry also applies.
Later observations cannot renew that interval. A shorter current observation
permanently shortens the request handle, including when concurrent provider
reads complete out of order. A final locked check applies the earliest observed
deadline; expiry stops subsequent provider reads. Checks reject cancellation,
expiry after blocking work, clock reversal and changes to principal, identity
policy, scopes or groups. Scope/group ordering alone is immaterial. Returned
slices do not alias the private original observation. A changed identity requires
a new authenticated request; an old request cannot silently continue under new
membership. Current browser checks resolve the original session without refresh;
only the initial authenticated ingress may rotate its credentials. Provider
tokens never enter a browser response or this public application handoff.

`Evaluator.EligibilityCurrent`, `Evaluator.ContextEligibilityCurrent` and
`ContextDownloadAuthority.CheckDownloadCurrent` consume the handle. Existing
token-string entry methods remain available and delegate to the same evaluation
path. Current identity is checked again after blocking permission/evidence reads;
the original identity deadline remains an upper bound. Existing target denies,
retained audiences, retention/recovery proofs, scope and final effect checks
remain required. No application or transport gains an alternative policy engine.

This handle is for one finite operation or authorization batch. It is not a
credential to persist with a capture, pass to a worker, or renew across a
long-running download. Those workflows need their existing current-authority
and cancellation composition for each bounded operation. Production transports
construct handles from protected services; no user input selects an implementation.
Test fakes implement ports solely inside tests.

## Verification and remaining composition

The sequential and concurrent shortening regressions failed before the handle
retained the earliest deadline; see [the failing log](../../test/results/context-identity-monotonic-before.log).
The corrected identity and browser/MCP/presentation race suites returned 0 in
[the focused rerun](../../test/results/context-identity-monotonic-after.log).
This extends the existing final socket-bound check without changing the session
lifetime or allowing an old request to refresh its authority.

`TMPDIR=/home/phil/.cache/asservat-build/tmp go test -race
./internal/application/identity ./internal/application/authorization
./internal/transport/browser` returned 0. The retained result is
[current-request-identity-race.log](../../test/results/current-request-identity-race.log).
Tests cover claim changes, reordered groups, defensive copies, original deadline
expiry during a read, original-request cancellation with a background consumer,
session revocation/disappearance during the final persisted read, current settings,
refresh only at ingress, CSRF before resolution and shared capture/read/download
evaluation without a bearer fallback.

These are component tests using synthetic identities and session stores. They do
not qualify public installation, OIDC deployment, workload discovery, capture
dispatch, catalog publication or native byte delivery. The shared investigation
application service and protected production composition remain required before
the first end-to-end workflow is enabled.

The owned `make identity-integration` run subsequently returned 0 with real
Keycloak, PostgreSQL and OpenBao. Named browser subtests bind/recheck the real
stored session, perform HTTPS local logout and require the old handle to deny
before its original deadline; neither current check rotates credentials or
recreates the SQL session. The [provider log](../../test/results/current-request-provider.log)
records eight passing parent/subtest entries in 4.465 seconds. Its
[environment report](../../test/results/current-request-provider-environment.json)
records 679 unchanged hashes and empty cleanup failures. Fixture administrator
setup remains synthetic and is not production installation authority.
