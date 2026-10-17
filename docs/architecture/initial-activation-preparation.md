# Gated installation preparation

ADR-120 is the explicit continuation of the stable ADR-117 root and ADR-118
private-state work. C-20 owns the closed root/capability DTOs. C-21 implements the
native producer and public credential binder. The private `initial-prepare`
command selects the continuation only when the immutable plan includes it.

`InitialPreparer.PrepareGatedPod` proves the original administrator, staging and
continuity guards, all nine declared object identities and the root. One retained
Pod operation ID and compiled-template digest precede its first POST. A missing
object can cause only the same named gated CREATE while no UID receipt exists.
After a receipt, missing/replaced/changed objects are unavailable; no replacement
is created. The observer checks exact metadata, unchanged gate, no node/start or
container execution, and the complete intended specification after a small
explicit list of known Kubernetes defaults. Actual specification digest and UID
are retained atomically, and original deadlines remain binding after rereads.

Every actual Pod POST first claims its own immutable request ID, local owner ID
and original interval of at most five seconds in the same root CAS. The fixed
budget is sixteen requests, including unresolved ones; exhaustion preserves the
original root and reports a qualified-recovery blocker. A fully received 201 with
an exact matching Pod or a structured 409 AlreadyExists can close only that
invocation. A later GET, another request's 409, local cancellation or an expired
interval cannot close a prior unknown request.

The local owner cancels and joins the whole preparation call, including final
root handling. `DrainPodCreateRequests` permanently stops new local CREATEs and
checks all persisted records. A locally retained positive result may finish its
original completion acknowledgement after a lost journal reply under fresh
current checks; its original request dates and completion instant never change.
A process that lost this private result cannot reconstruct it from a Pod lookup.
This is healthy Pod-request completion only: it grants no Pod DELETE, launch,
credential retirement or activation authority. The command reports unresolved
original requests explicitly and preserves their occupied names.

The added continuity branch matches only DELETE of this exact Pod name. It does
not create a generic Pod mutation exception: the original staging/final namespace
guards still govern create, scheduling, status and launch. This branch applies
only to the new capability. VAP self-exclusion and trusted cluster-administrator
bootstrap boundaries from ADR-117 remain unchanged.

`InitialPreparationCredentialBinder` is a concrete native read/CAS component; it
has no SQL or provider effect writer. It checks the pinned original private
material, actual declared Namespace/account receipts, recorded gated Pod UID/spec,
current final workload protection and immutable full startup input UID/hash.
Only then can it record one original fifteen-minute public interval. Replay checks
the same material UID and startup digest and returns unchanged dates, including
expired dates needed for exact cleanup. It returns the earliest original current
observation deadline separately. Its caller must preserve that deadline and use
the existing SQL validity checks; the binding is not an effect permit.

The finite activation inventory is thirteen additional Kubernetes objects, plus
the original nine: Pod, witness and fleet source, three policy/binding pairs,
startup ConfigMap, probe token anchor, SQL-state Secret and provider Secret.
Bootstrap-owned desired/probe/protection/private resources and later runtime
component provisioning are distinct finite phases. This is not a generic resource
engine, and secret/provider effects do not inherit declarative replay authority.

## Qualification and remaining work

Focused unit/race coverage passed for the gated producer, original credential
CAS and request-drain protocol. Integrated affected races/vet and contract gates
pass. The selected native Kubernetes suite passes both healthy and uncertain
subfixtures, with 35 named entries, unchanged source and complete cleanup; actual
logs and fixture boundaries are recorded in
[implementation progress](../implementation-progress.md). The native final guard
transition is supplied by the fixture administrator, not the product handover.
Tests distinguish safe defaulting from
injected executable content, unknown first CREATE from a recorded UID, and one
original interval from a retry timestamp. No native result is implied by a fake
API echo or generated policy string.

The current command reaches a verified gated Pod only. Final typed public-input
and guard producers, durable one-use private/provider effects, independently
qualified staging handover and ungating, activation reconciliation and positive
credential and Pod retirement remain required. Unknown request reconciliation
and the healthy completion-to-retirement composition remain required. The credential binder consumes final inputs;
it does not manufacture them. A retained terminal Pod protects an unresolved name
but is not the final cleanup behavior. Old roots cannot acquire this capability
by changing their current desired plan. No public workflow or Helm runtime is
enabled by this stage.
