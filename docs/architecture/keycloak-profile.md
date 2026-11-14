# Keycloak reference identity profile

Keycloak is the first supported and tested provider for browser sign-in and
MCP access (REQ-AUT-001, TASK-07, [ADR-053](../decisions/053-keycloak-access-profile.md),
[ADR-335](../decisions/335-usable-by-default.md) D4/D5/D14).
With `services.identity.provider: external`, the realm stays operator-managed;
the [bundled-services profile](../installation/small-profile.md) selects
Keycloak explicitly and prepares its own realm. Selecting an external provider
never changes an existing realm. The profile is selected in the mounted
identity configuration (`oidc.Trust.Profile`), never guessed from a token. It
reuses the generic HTTPS/JWKS and signature verification of
[identity eligibility](identity-eligibility.md).

## Token rules

- Access tokens require header `typ=JWT`, signed claim `typ=Bearer`, `azp` and
  the one configured resource audience. If `client_id` is present it must equal
  `azp`.
- ID and refresh tokens are rejected, as are delegation, impersonation (actor
  claims) and proof-of-possession tokens.
- Group membership comes from the configured groups claim (`identity.groupsClaim`,
  default `groups`), as group names. An absent claim means no groups.
  Malformed, null, duplicate or oversized claims fail verification.
- A token without `sub` fails verification; the username comes from
  `preferred_username` unless `identity.usernameClaim` says otherwise.

## Realm configuration

- An audience mapper adds the API audience.
- Keycloak's standard Group Membership mapper emits the `groups` claim with
  full group paths (`/payments`, `/platform/sre`), so subgroups with equal
  names stay distinct. Bindings and `identity.administrators` use those paths.
  Renaming or moving a group changes its path; bindings naming the old path
  stop matching until they are updated, as with Kubernetes OIDC groups.
- Keep the `basic` client scope, which supplies `sub`, and the `profile`
  scope, which supplies `preferred_username` and the display name.
- The console client and the MCP client get `evidence:share` as a default
  client scope ([ADR-232](../decisions/232-concrete-evidence-share.md)).
- The human clients use authorization code with S256 PKCE; direct password
  grants, implicit flow and service accounts are disabled. The MCP client is a
  public client whose redirect URIs are the loopback addresses on any port
  (RFC 8252 §7.3), so desktop MCP tools need no per-tool registration.
  Workloads use a separate confidential client with browser and password flows
  disabled.
- Step-up is not configured by default. An operator who enables
  `approvals.stepUp` configures a Keycloak authentication flow whose level of
  assurance maps to the configured `acr` values; `max_age` re-authentication
  is the minimal working setup.

Group membership is recomputed at every token issuance, including refresh, and
is valid for the access token's lifetime (Keycloak default five minutes).
Closing a provider session does not revoke already issued JWTs; Asservat's
identity configuration, checked once per operation, can remove a client or
subject independently. Asservat needs no realm-admin credential or Admin API
access at runtime.

## Bundled realm

The bundled realm creates the console client, the MCP client and the group
`/asservat-admins`, which is the default of the Helm value `administrators.groups`. The
chart creates an initial administrator user named in values, with its password
read from an existing Secret or generated into one; that user belongs to
`/asservat-admins`. Administrators create further users in the Keycloak admin
console with a temporary password, which Keycloak makes the user replace at
first sign-in, and add them to team groups. There is no self-registration and
no default password. The realm's groups and clients are reconciled on
`helm upgrade`.

Recurring team policies do not depend on an author's SSO session
([ADR-059](../decisions/059-unattended-policy-authority.md),
[background identity research](../research/background-identity.md)); no
directory-reader or offline credential is required.

`make identity-integration` runs a pinned Keycloak fixture with synthetic users
and groups against the product verifier and browser sessions
([browser sessions](browser-sessions.md)). Results are recorded in
docs/implementation-progress.md.

Sources: [Keycloak 26.8.0 release notes](https://www.keycloak.org/2026/10/keycloak-2680-released)
(actor claims on impersonation),
[group membership mapper](https://github.com/keycloak/keycloak/blob/26.8.0/services/src/main/java/org/keycloak/protocol/oidc/mappers/GroupMembershipMapper.java)
(emits names or full paths),
[group administration](https://www.keycloak.org/docs/latest/server_admin/index.html#_groups),
[Kubernetes OIDC groups claim](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens),
[RFC 8252 §7.3](https://www.rfc-editor.org/rfc/rfc8252#section-7.3)
(loopback redirects on any port).
