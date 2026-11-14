# Keycloak reference identity profile

Keycloak is the first supported and tested provider for browser sign-in and
MCP access (REQ-AUT-001, TASK-07, [ADR-053](../decisions/053-keycloak-access-profile.md)).
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
- Only the `asservat_groups` claim supplies group membership, as stable group
  IDs. Group names and paths never confer access. An absent claim means no
  groups. Malformed, null, duplicate or oversized claims fail verification.
- A token without `sub` fails verification.

## Realm configuration

- An audience mapper adds the API audience.
- A multivalued User Attribute mapper for `asservat_group_id`, with aggregation,
  emits `asservat_groups` only in access tokens. Each group's attribute holds its
  native group UUID. Inherited groups contribute their IDs; renames do not
  change them. Group IDs are never recycled.
- The attribute is protected against user writes; user, group, client and mapper
  administration is restricted; unmanaged attributes are disabled.
- Keep the `basic` client scope, which supplies `sub`.
- The console client gets `evidence:share` as a default client scope
  ([ADR-232](../decisions/232-concrete-evidence-share.md)); MCP clients request
  it as an optional scope.
- The human client uses authorization code with S256 PKCE; direct password
  grants, implicit flow and service accounts are disabled. Workloads use a
  separate confidential client with browser and password flows disabled.

Group membership is recomputed at token refresh. An accepted group assertion is
bounded from the access token's original `iat`. Closing a provider session does
not revoke already issued JWTs; Asservat's identity policy, checked once per
operation, can remove a client or subject independently. The installation guide
documents these realm settings; Asservat needs no realm-admin credential or
Admin API access at runtime.

Recurring team policies do not depend on a creator's SSO session
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
(emits names/paths),
[user attribute mapper](https://github.com/keycloak/keycloak/blob/26.8.0/services/src/main/java/org/keycloak/protocol/oidc/mappers/UserAttributeMapper.java)
(aggregation),
[group administration](https://www.keycloak.org/docs/latest/server_admin/index.html#_groups).
