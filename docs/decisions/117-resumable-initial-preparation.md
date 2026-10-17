# ADR-117: Resume fixed declarative setup after a lost create reply

Status: accepted implementation refinement; native qualification pending.

An ordinary interrupted installation must resume its original plan. ADR-102's
lookup-only rule is still required for credentials, provider calls and effects
that might execute again. It needlessly strands a fixed declarative Kubernetes
object when no current object can be found after a lost CREATE response.

Use one stable bootstrap namespace outside the target namespace. Helm owns the
immutable desired plan, continuity/staging policies and bindings, and the bounded
bootstrap/probe inputs. The supervisor owns the mutable root ConfigMap. Helm
must not render its mutable data, roll it back, delete/recreate it, or generate
new plan/request IDs on an ordinary upgrade. Exact pinned policy metadata must
not change merely because a chart version label changed. A changed guard/spec
requires explicit requalification, not silent adoption of new pins.

The public root is long-lived desired-state provenance, with no arbitrary
expiry. Current administrator and independently probed guard observations still
expire within their original five seconds. Each run is finite. Issued SQL,
Kubernetes or provider credentials retain their own original deadlines. Resume
never resets those credentials, an uncertain operation, or the root identity.

Repeat CREATE only for the compiled nine-object set: one Namespace, two
ServiceAccounts with automount disabled, two Roles, two RoleBindings, one
ClusterRole and one ClusterRoleBinding. Retain the exact group/kind/namespace/name,
installation/request/operation markers, public specification digest and any
observed UID. One pending entry occupies its original slot. GET must verify the
full typed shape; an observed UID cannot be replaced. An unacknowledged root CAS
never authorizes an effect in that invocation. A later invocation may use the
persisted identical declarative intent only under unchanged continuity protection.

Continuity protection prohibits deletion of the root, bootstrap/target namespaces
and these nine resource keys. Roles and bindings can make only their exact
compiled-original to canonical-empty transition, preserving identity and other
fields. Empty rules/subjects cannot be refilled. The occupied key remains: a
network-delayed original CREATE then returns AlreadyExists, including after setup
permissions were retired. Observing a winning resource does not prove all older
requests completed, so timeout/winner observation never permits deletion/reuse.
There is one finite inventory per installation, not an accumulating abandoned-name
scheme or a general resource engine.

Kubernetes deliberately excludes ValidatingAdmissionPolicy and its bindings from
policy matching. These guards therefore remain trusted bootstrap objects; they
are excluded from the retriable set. A cluster administrator capable of replacing
those guards is part of the installation trust boundary. Current proof cannot
establish historical cleanliness after an out-of-band cluster restore or guard
replacement. This slice supplies no such recovery authority.

Secrets, TokenRequests, provider effects, executable Pods/Jobs, witness consumption,
SQL activation and scheduling-gate removal remain excluded. Their existing
one-use or independently qualified protocols are not relaxed. The declarative
checkpoint does not finish the preparation/credential/activation/retirement
supervisor or enable Helm runtime services; the same supported installation path
must compose those remaining typed effects.

Evidence and implementation scope are described in
[initial preparer](../architecture/initial-preparer.md). This refines ADR-102 only
for this continuously protected finite set and leaves its original APIs unchanged.

Primary references: Kubernetes [object names and UIDs](https://kubernetes.io/docs/concepts/overview/working-with-objects/names/),
[CREATE semantics](https://kubernetes.io/docs/reference/using-api/api-concepts/),
[admission-policy self-exclusion](https://kubernetes.io/docs/reference/kubernetes-api/admissionregistration/validating-admission-policy-v1/),
and [CEL variable scope](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/).
