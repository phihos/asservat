# Initial preparation creation journal

[ADR-102](../decisions/102-initial-preparation-journal.md) gives C-21's installation
producer a durable record before creating subsequent Kubernetes resources.
C-20 owns the closed private [wire document](../../specs/contracts/initial-preparation.schema.json).
The existing preparation ConfigMap remains the independently denied staging
probe; its public record adds no credential access or evidence permission.

`InitialNamespaceCreator.CreateJournal` first verifies the exact complete
namespace/guard references, authenticates the configured administrator and sends
one create-only ConfigMap request. It records the original installation/request,
public preparation-plan digest and acknowledged namespace/guard pins. It does not
adopt a collision or retry an unknown create. An acknowledged ConfigMap UID may
be returned alongside a failed final check solely for uncertainty tracking.
The supervisor must persist that UID and must not start subsequent resource
operations until the independently authenticated staging probe is qualified.

`InitialPreparationJournal` requires that exact UID, the same namespace/policy
plan, guard identities and API endpoint. Every operation authenticates the
administrator and independently proves the native staging denial. Namespace and
journal replacement, changed installation/request/plan, missing guard or expired
original observation makes the facet unavailable. The whole read/update/postcheck
is bounded by the earliest caller/observation deadline, at most five seconds.

| Operation | Behavior |
| --- | --- |
| `Read` | Validate the complete root and bounded ordered create history; supply no new attempt |
| `Begin` | Append one public create intent using the journal's UID/resource version; only an acknowledged first update reports `Fresh` |
| `Begin` replay | Return the existing record with `Fresh=false`; never retry its external create |
| `Observe` | Attach the separately verified exact UID/resource-version receipt to the pending intent |
| `Observe` replay | Accept the identical receipt without a write; reject replacement |

The list has at most 64 entries, unique operation UUIDs and unique kind/name
targets. Only its last entry can remain pending, and no subsequent entry is
admitted until that receipt is verified. The total document is at most 48 KiB.
Allowed resource kinds are the finite setup account, RBAC, ConfigMap, Secret,
Pod and native admission resources. Names and digests are bounded/canonical;
unknown fields, duplicate JSON keys and receipt aliases/nulls are rejected.
`specDigest` describes only the intended public resource shape. Never hash
secret payloads into this public document.

The adapter performs exactly one conditional update. A conflict or unknown reply
does not trigger an automatic update retry or a matching-value GET that claims
freshness. After restart the same intent is lookup-only. `Fresh` tells the
supervisor it won scheduling for that one attempt; it is not a portable permit,
and replaying a returned Go value cannot authorize another effect. The supervisor
must independently check current protection, target specification and creation
receipt. A pending intent whose target is absent remains uncertain until the
separate reconciliation protocol can resolve it; absence alone cannot justify a
second create.

The staging facet becomes unavailable when its guard is retired. Production
root retention, preparation inventory/effect composition, guarded handover,
provider credentials and retirement, post-handover historical access and the
full Helm flow remain separate work. Neither fixture-supplied plan digests nor
this journal establish original installation trust or recovery authority.
Measured test scope belongs to [implementation progress](../implementation-progress.md).

## Predefined account and RBAC producer

`InitialPreparationWorkloadDigest` hashes the validated public workload plan;
`InitialPreparationResources` requires that exact digest in the journal and the
same namespace/startup-input name. The full execution plan retains its separate
digest with actual Pod, source and provider pins. Derived Role/RoleBinding names
must already be valid before any resource request is made.

The producer supports exactly the writer ServiceAccount, both predefined
namespace Roles/RoleBindings and the predefined ClusterRole/ClusterRoleBinding
from `BuildInitialInstallerWorkload`. The initial probe account precedes this
phase. It accepts no arbitrary Kubernetes body, Pod, Secret or additional RBAC
rule. Provider credentials and the gated Pod require their own producers.

`Ensure` reads the original journal and either reuses an existing target intent
or reserves one new random operation UUID. Only a fresh acknowledgement leads
to one POST. The object carries the installation/request/operation markers;
successful and recovered replies are decoded into empty typed objects and must
match the exact intended public fields. Unrelated labels, annotations, owners,
finalizers, automatic token mounts, extra role rules/subjects and role aggregation
are rejected. The server's actual UID/resource version is recorded only after
that verification and renewed native checks within the original bounded call.

A lost POST reply permits one exact GET under that recorded intent. A later
`Ensure` never recreates the resource: it reads the original UID, markers and
desired fields. An absent or changed target remains unavailable. When the first
receipt already exists, metadata resource-version progress does not rewrite the
original receipt; the current shape and retained UID must still match. Any
mutation or verification failure leaves the durable intent/known receipt in
place. Cluster-scoped RBAC administration remains a trusted installer/operator
boundary; namespace admission does not protect those cluster-scoped objects.
