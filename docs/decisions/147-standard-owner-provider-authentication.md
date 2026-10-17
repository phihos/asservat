# ADR-147 — Standard owner provider authentication

Status: selected under continued implementation authorization. Requirements:
REQ-DEP-001, REQ-DEP-003 and REQ-DEP-005. This source-stage component fixes the
public profile and generated authentication recipes; actual provider setup,
login/renewal, transport lifetime and installed qualification remain pending.

The private owner needs sustained audit wrap/unwrap and paired certificate
signing. The original finite installation issuer has different purposes,
parent-revocation and lifetime rules. Keep it unchanged. Select standard OpenBao
Kubernetes authentication for ongoing owner credentials, with four generated
roles/policies for those exact effects. Bind the original account/namespace,
dedicated projected audience, verified auth mount and original provider recipes.
Keep all native workload, accepted source/recovery, SQL and signing-attempt checks
independent and current. A provider credential does not activate a process.

The new closed [public profile](../../specs/contracts/owner-provider-auth.schema.json)
contains only the original ServiceAccount and selected audit Secret identities,
auth mount/accessor and public recipe digest. Role/policy names, audience,
filenames and timing are generated. Role/policy names use the full SHA-256 of
a canonical domain-separated original installation/cluster/namespace/account
scope, including original UIDs, so separate owner scopes do not share them; there is no caller-selected purpose or TTL.
The first service-token profile has at most 300-second leases and an original
900-second hard maximum, no period/default policy and no identity-policy grant.
Only self lookup/renew/revoke accompanies each exact provider effect. Runtime
has no provider administration, token-creation or accessor-discovery privilege.

Protected setup verifies complete mount, auth-role, canonical ACL and Transit/PKI
recipes, including accepted roots and leaf constraints. Verify direct and
effective token policy sets at login, positive renewal and exact same-token
reconciliation. Do not add policy, role or self-lookup requests to every crypto
effect. Provider administrators are trusted; these observations do not promise
instantaneous provider-policy drift detection or an atomic fence against their
edits. Finite acknowledged credential leases and current application authority
remain binding. Unknown login responses consume their bounded attempt and are
not automatically replayed. They do not prove no token was created.

A concrete four-purpose process owner must serialize each purpose's control
calls, retain only current/draining credentials, use finite failure backoff and
cancel/join all owned calls. Renewal changes only subsequent observations; it
cannot extend an admitted operation's original expiry. The existing bytes-only
TokenSource is insufficient to convey this bound, so runtime integration must
retain a private lease through HTTP response closure. No per-revision cache or
custom ongoing token-issuer journal is introduced. Provider-wide quotas remain
external policy, not a claimed global product token counter.

Bao in Kubernetes can use its own rotating reviewer token. External Bao requires
provider-owned reviewer rotation and API/CA reachability; the owner never gains
TokenReview merely to authenticate to Bao. No fallback to caller-as-reviewer or
offline JWT authentication is part of this profile. Already issued provider
tokens are not claimed to revoke instantly when a Pod or its JWT disappears.

For S3, select an explicit operator-managed scoped Secret. Asservat documents and
qualifies the required owner audit operations without administering external IAM.
Credential rotation belongs to the separately protected original Secret/provider;
endpoint, bucket and purpose remain pinned. A future workload-identity profile
requires separate review. Local-key deployments remain independent of Bao and
retain their existing protected key-service and issuer prerequisites.

Keep this DTO standalone until its actual receipt-bound projection and runtime
selection are implemented together. Merely adding an optional recognized field
to OwnerDeployment would let the old loader ignore it and use legacy token files.
The current closed decoder must continue rejecting it. Later integration must
reject unqualified or mixed legacy/new selections before any effect, use a fresh
explicit installed layout, and preserve omitted legacy bytes. Component recipe
checks, actual provider qualification and deployed owner execution are distinct;
none enables public serving or the Helm runtime on its own.

The [owned native provider qualification](../../test/results/owner-provider-auth-native-check.log)
passes all six scenarios with the pinned provider and a real Kubernetes API.
It covers the four generated login/renewal profiles, first effects and purpose
separation, audience/policy rejection, original-Pod deletion, external reviewer
rotation and original service-account UID matching. Privileged fixture setup
does not supply an installed credential owner or accepted operation authority.
Elapsed 600-second expiry, kubelet renewal and the installed four-purpose
supervisor remain unqualified; the profile is still standalone and unselected.

The private four-purpose lifetime component separately passes compilation,
25 selected top-level race tests and vet. These tests cover serialized control,
finite backoff, rotation with retained original effect leases and joined shutdown.
The result does not qualify the installed supervisor or select this provider
profile; the receipt-bound loader and concrete effect composition remain pending.

The [extended native provider test](../../test/results/owner-provider-leased-effects-native-check.log)
also passes the actual maintained Transit/PKI effects through the four leased
clients, verifies both issued certificate purposes and observes denial of all
four tokens after joined retirement. Its installation, recovery and permit facts
remain synthetic. This qualifies provider compatibility, not installed runtime
selection or the long-duration projected-token/provider-token rollover.

Mechanism references: [Kubernetes auth](https://openbao.org/docs/auth/kubernetes/),
[role API](https://openbao.org/docs/api/auth/kubernetes/),
[token lifecycle](https://openbao.org/docs/concepts/tokens/),
[policy behavior](https://openbao.org/docs/concepts/policies/). Consulted current
documentation is not evidence for the repository's exact pinned provider image.

The installation-only read verifier now has passing component checks. It uses a
separate inspection credential and named read-only requests, never the runtime
credential or a provider administrator write. The initial installed verification
profile requires an explicitly configured external reviewer with exact API/CA,
local fallback disabled and a positive configured-presence indicator. That
indicator does not establish possession, rotation or TokenReview authorization.
The in-cluster rotating-reviewer mode remains separately unqualified; it is not
silently inferred from a missing credential.

A separate pure setup recipe retains the existing authentication bytes and adds
explicit pool-scoped PKI constraints. Provider DNS/URI globs are not process
attestation; every actual leaf still needs the exact runtime CSR/native/SQL
checks. The role explicitly disables wildcard certificates, arbitrary names,
CSR identities and additional usages. Setup checks bind the complete original
public input, pool and roots and expire within their original five seconds.
They are current observations, not an atomic fence against a trusted provider
administrator's changes. Provider reads precede installation SQL locks; current
native/SQL checks and the original observation deadline remain required afterward.
The first complete native attempt failed on the original mount read. The pinned
provider accepts the equivalent `sys/mounts/auth/<mount>` with named read-only
ACLs; the verifier and automation artifact now use that path. Do not require
administrative inspection or retune a shared authentication mount. Fixed role
TTLs and actual token lifetime validation remain binding.

The provider's permissive certificate-date defaults are explicitly replaced with
`not_after_bound=ttl-limited` and `not_before_bound=forbid`. Role TTL and maximum
are both the existing 20-minute period plus one-minute early-renewal ceiling;
the actual fixed UTC certificate periods are unchanged. Isolated actual signing
accepts 20m30s and rejects 22m and explicit not-before. The complete native retry
and installed producer/runtime qualification remain separate pending gates.
See the [diagnostic archive](../../test/results/owner-provider-setup-diagnostics/archive.json)
and [correction component result](../../test/results/owner-provider-setup-correction-integration.json).
The public-input observation digest retains exact int64 generation values;
canonical floating-point rounding must never collapse distinct generations.


The corrected [complete native retry](../../test/results/owner-provider-setup-native-retry-result.json)
now passes the read-only setup verifier and subsequent actual leased Transit and
both PKI effects with the generated pool-scoped roles. All seven child scenarios
pass, including configured reviewer rotation and original account identity.
This supersedes the pending complete retry above; installed producer/runtime and
long-duration credential turnover remain separate unqualified boundaries.
