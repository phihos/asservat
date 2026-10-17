# Private initial preparation and probe issuance

This extends [ADR-123](../decisions/123-typed-initial-installation-inputs.md) and
the [public input producer](initial-final-inputs.md). C-20 owns the closed private
wire document; C-21 owns the Kubernetes producer and pure provider-input checks;
bootstrap composes them in the existing private `initial-prepare` command.

A new installation explicitly pins one mutable bootstrap Secret UID and one
Kubernetes API audience in its original desired plan. The original compiled
continuity policy protects that Secret before credential issuance. The desired
plan belongs to Helm; mutable progress belongs to the producer. Helm must not
rewrite that progress during upgrades or rollback. An existing plan without the
private fields keeps exactly its original compiled policy and cannot silently
acquire this continuation.

The trusted bootstrap creates the Secret with only format, installation ID and
request ID. The producer binds the actual original root UID and plan digest by
UID/resource-version CAS. The private document is at most 16 KiB; the public root
contains neither its payload nor a secret-payload digest. There is one probe
anchor intent/receipt and one token claim/response, with no unbounded history.
This adds exactly one bootstrap-provided private Secret and one producer-created
probe anchor to the finite installation inventory, plus one TokenRequest effect;
no additional public create-journal entries are introduced. The existing public
journal still has nine declarative resources, nine final inputs and at most
sixteen Pod request claims within its original 48 KiB ceiling.
The anchor is an immutable empty Secret in the target namespace. The existing
root keeps the namespace, account and still-gated Pod identities independently.

The private-capability continuity guard permits only a listed administrator's
CREATE on the exact probe account token subresource: one configured audience,
600 seconds and a v1 Secret bound to the fixed probe anchor name with a UUID.
It does not authorize a different account, audience, duration or binding. The
producer independently matches the original anchor UID and the current account;
this policy clause supplies neither a fresh claim nor a retry permission. Existing
plans without private state retain their original policy bytes.

Only the first acknowledged token-claim CAS permits a TokenRequest. Its original
interval is at most five seconds. The request binds the exact anchor Secret and
probe service account and asks for 600 seconds with the explicitly configured API
audience. The outer 605-second bound covers only processing within that original
five-second interval; the actual returned expiry is retained unchanged. An
unknown issuance is not repeated. A later GET or token review cannot manufacture
its missing response or prove no effect.

The returned token passes online TokenReview for that audience and original
account. Only after signature/audience authentication does the supported profile
inspect the signed Secret identity and original issued/expiry fields. TokenReview
omits Secret identity from UserInfo.Extra. Live original account and anchor reads
remain mandatory because Kubernetes can cache successful authentication. This is
a qualified Kubernetes token profile, not acceptance of arbitrary JWT shapes.

A positively reviewed response is retained by its live producer and persisted
into the same private Secret. A lost persistence reply can be reconciled by exact
current state or that same live producer's original positive response. Another
process with only a claim cannot issue again. Replays retain the exact token and
expiry, require current administrator/continuity/staging checks and finish within
the earliest original observation deadline. The method has separate current five-second root/anchor and token phases; this
is not an aggregate five-second limit on the whole preparation method. Each phase
retains its original bound, and an earlier caller deadline still applies.
Concurrent claim losers receive no issuance permission. Close rejects new local ownership, cancels and joins all
admitted calls, then drops retained responses. This does not promise Go heap
sanitization or server-side completion of an unknown request.

The guard permits one canonical inert private map plus immutable=true and then
rejects any return to mutable progress, replacement or deletion. The product
clearing operation is deliberately not exposed until credential revocation and
writer joining are composed. The fixed occupied key is finite installation
inventory. The native test's explicit administrator terminal transition tests
that guard only; it does not claim credential retirement. A cluster administrator
who can replace the guard remains within the trusted bootstrap boundary.

Public Kubernetes/PostgreSQL/object-store/key-service settings share pure checks
before any preparation mutation: HTTPS origins/ports, DER CA anchors, bounded SQL
settings and key-provider names. No connectivity test or provider mutation is
used to validate syntax. Current provider authorization, role existence and
backend capabilities remain separate. Malformed public input therefore fails
before it consumes a one-use preparation effect.

Focused unit/race and schema checks cover original-token replay, concurrent
issuance, lost claim/response persistence, unknown or incorrectly bound replies,
expired positive replies, replacement private UIDs and unchanged historical
policy bytes. The isolated native fixture source covers real TokenRequest,
bound-secret claims, current replay and native continuity enforcement. Its actual
external qualification is pending; it must not be reported as passed merely
because its source compiles.

Required continuation remains original SQL-material binding and temporary role
provisioning; immutable target provider projections; actual scoped provider
issuance/revocation; independent final guard proofs, one-use staging handover and
original-Pod ungating; successful activation reconciliation and positively joined
credential retirement. Private probe readiness is not installed runtime readiness.
A lost/expired original credential still needs qualified recovery; resetting the
root, deleting occupied keys or silently renewing issuance is not a recovery path.
The chart and public acquisition remain unavailable.

Primary sources: [Kubernetes service account administration](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
and [the upstream bound-token claim implementation](https://github.com/kubernetes/kubernetes/blob/v1.35.3/pkg/serviceaccount/claims.go).
Native qualification of the supported API profile remains necessary.
