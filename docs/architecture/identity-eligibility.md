# Identity and ordinary eligibility

Scope: C-02 identity, C-03 authorization, C-21 protocol adapters and C-24
values; REQ-AUT-001/002, REQ-PER-001/006/008, TASK-07, S-01/S-02. The
[identity research](../research/identity-foundation.md) and
[settings research](../research/identity-settings-foundation.md) record the
external sources. This boundary returns eligibility, not an execution permit or
disclosure authorization.

## Credential verification

The generic adapter accepts RFC 9068 JWT access tokens signed with RS256 for one
resource audience from a configured HTTPS issuer. It uses go-oidc verification
and go-jose JWK parsing, and additionally checks the access-token media type,
exact issuer, resource audience, `client_id`, consistent optional `azp`,
required timestamps and token ID, and bounded scope/group claims. ID tokens,
opaque, encrypted, delegated and proof-of-possession tokens are rejected.
Providers with a different access-token layout get an explicit profile, as the
[Keycloak profile](keycloak-profile.md) does; guessed e-mail or group display
names are never accepted.

Issuer, audience, JWKS URL, CA trust and cache limits come from the mounted
identity configuration. Token fields cannot choose endpoints, algorithms or key
URLs. Requests use verified HTTPS without ambient proxies, cookies, forwarded
bearer tokens or redirects. Where `key_ops` is present, only verification use is
accepted.

| Input/work | Bound |
| --- | --- |
| Compact token / decoded header / decoded claims | 32 KiB / 2 KiB / 24 KiB |
| Header / claims JSON | 64 / 2048 tokens, depth 4 / 8; duplicate keys, invalid Unicode and ambiguous aliases rejected |
| JWKS response | 128 KiB, 8192 JSON tokens, depth 8, at most 32 keys |
| Signature keys | RSA public keys, 2048–8192 bits; private/symmetric material rejected |
| JWKS cache | Last-known-good key set per issuer; refreshed when a token names an unknown `kid` |
| JWKS refresh | Serialized, at most one attempt per second per issuer; no per-attacker-key cache |
| Network I/O timeout | 5 seconds |
| Signed groups / scopes | At most 256 stable IDs / 64 scopes |

The JWKS cache follows go-oidc `RemoteKeySet`: keys stay valid until a refresh
replaces them, and an unknown `kid` triggers one rate-limited refresh. A failed
refresh keeps the last-known-good set. Key rotation at the provider therefore
works without a timer, and a provider outage does not reject tokens signed by a
cached key. Revoking an issuer or client is done in the identity configuration,
not by expiring keys.

## Organization eligibility and policy

`identity.Service` takes verified claims from `TokenVerifier` and checks them
against the current installation identity policy for that exact issuer. A valid
signature alone is insufficient: the policy must admit a stable subject or a
group, and the registered client. Client IDs and resource audiences are
distinct.

Each client is configured as human-only or workload-only; there is no human
default for a mixed client. Group eligibility requires a provider configuration
that signs the complete list of stable group IDs and refreshes it at token
issuance, including refresh. The RFC 9068 profile requires an explicit, possibly
empty groups array; the Keycloak profile uses its dedicated stable-ID mapper.
Group names or paths are never a fallback. A group assertion is accepted for at
most five minutes from the token's original `iat`.

The policy is `identity.json`, validated against the
[identity settings contract](../../specs/contracts/identity-settings.schema.json)
([example](../../examples/identity-settings.json)). The Helm chart renders it into
a ConfigMap. `IdentityPolicyClient` reads it from the mounted file, or through a
shared informer, and keeps the parsed policy valid until a change replaces it.
A watch or parse failure keeps the last valid policy and reports the error; it
never falls back to a permissive policy. Unknown fields, duplicate clients,
unqualified identity classes and invalid group bounds are rejected when the new
content is parsed. Client or subject removal takes effect when the changed
content arrives.

Each operation evaluates eligibility once and reuses the result within the
caller's handle lifetime
([current request identity](current-request-identity.md); 30 s, ADR-311). No
SQL permission editor, public permission CRUD API, tenant abstraction or
permissive development identity exists.

## Ordinary permissions and retained audiences

`authorization.Evaluator` resolves the caller, takes the current permission
projection for the exact cluster/namespace/workload/pod and checks ordinary
target entitlement before looking up evidence, so an ineligible caller cannot
probe artifact metadata. Errors expose bounded reason codes, never token claims
or downstream error text.

Permissions:

- Context requests need `evidence:capture`; reads need `evidence:read`;
  downloads also need `evidence:download`.
- Maintainers may request context; readers and owner teams may read and
  download permitted approved evidence. An approver role alone confers neither
  collection nor reading. Ordinary approved downloads need no extra approval.

Explicit denies subtract the named role's operations. The permission projection
is maintained from permission-source watch events
([permission observation](permission-observation.md)); allows and denies come
from the same cache. While that cache is unavailable after a watch failure and
before its relist completes, eligibility is denied. Projections have bounded
allow/deny rows and no catch-all fallback.

Evidence reads also intersect the caller's current assignments with the
artifact's retained audience. The audience is stored as issuer plus stable
subject or stable IdP group ID, with role (D11). A new owner team cannot read old
evidence through ownership alone. New members of a still-listed group can read.
Several original teams stay independently eligible. The creator gets no special
access.

`Result.ContributingAssignments` explains why the caller qualifies. It is not
the default audience for a new capture. `Evaluator.ContextEligibility` returns
caller eligibility and, separately, the complete default audience from the same
projection: all current reader, maintainer and owner assignments for the
target, excluding approver-only assignments and denied subjects, with at most 32
entries and no truncation. It performs no artifact lookup or acquisition.

Read checks may evaluate a larger current projection before intersecting it with
the artifact's audience, so assignments added later never block an existing
reader. A stored artifact keeps at most 32 audience entries.

Raw operations, shares, approvals, step-up authentication, collection
ceilings, capacity, execution, audit and disclosure are composed by their own
components before any effect. `AudienceReader` reads only published catalog
entries, never stored but unpublished custody rows.
