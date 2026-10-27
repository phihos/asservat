# ADR-253 — Approval step-up sign-in

Date: 2026-10-27. Status: implemented; component verification below, real-provider qualification pending.
Requirements: REQ-AUT-003, REQ-INV-001; TASK-07/08; S-04 increment 12b subset.

## Problem and decision

ADR-249 requires recent independent approver assurance, but the console only
instructs reviewers to sign in again. Normal login does not request the configured
assurance or fresh authentication. A reviewer cannot complete the intended flow.

Add GET `/auth/step-up` on the existing authentication boundary and a "Sign in
with step-up" link beside the approval controls. The link returns to that exact
approval page. The endpoint accepts only the existing local `return_to` path;
provider parameters and callback addresses are not caller inputs. It reads the
current protected identity policy, verifies its issuer and human console client,
then uses its configured ACR values with `max_age=0` on the pinned provider URL.
It reuses existing random state, nonce, PKCE, encrypted five-minute challenge,
browser binding and one-use callback. No additional credential or SQL schema.

[OIDC Core 3.1.2.1](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
defines `max_age=0` as fresh authentication and `acr_values` as requested assurance.
The latter is voluntary; neither URL nor callback success grants approval.
The existing signed access-token `acr`/`auth_time` check under current policy
remains mandatory on each approval decision. A changed signed-in account gets
that account's permissions and self-approval checks. No pending decision is
replayed automatically after login. Return to the exact plan and decide explicitly.
Unconfigured/stale/unavailable settings refuse the attempt and direct the user
to an administrator without exposing upstream errors.

## Complexity gate

1. Observed: every reviewer lacking recent assurance has no direct console path.
2. Accepted: yes, ADR-249 and S-04 increment 12b explicitly require the button.
3. Typical: yes, sensitive capture approval.
4. Precedent: OIDC Core fresh-authentication and requested-ACR parameters above.
5. Added privileges/credentials/exposure: 0; one login-mode route under existing TLS.
6. Added persisted/degraded states: 0; current unavailable response reused.
7. Added configuration: 0; use existing protected stepUp settings.
8. External dependency: same configured OIDC provider; no additional component.
9. Cost: one existing cached policy read per deliberate step-up; normal login
   unchanged; one existing challenge row; no work per node, cluster or capture.
10. Rollback: remove link/route; challenges use unchanged login format.
11. Smaller fix: a normal sign-in link does not request fresh/configured assurance.

## Verification and limitations

Targeted Go race tests cover current policy, missing/stale/changed settings,
client removal, cancellation, policy expiry during work, closed query parameters,
PKCE/state/nonce/callback preservation, invalid ACR lists and unchanged normal
login. React tests check the exact local return link. Native Keycloak step-up
with an actual LoA flow and installed browser interaction remain pending;
component tests do not claim that qualification. No policy-grant or observation
spending behavior is added by this change.
