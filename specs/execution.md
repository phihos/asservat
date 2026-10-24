# Accepted execution identities and digest scopes

These contracts separate request provenance, collection approval and sharing. A digest proves identity of a scope, not authority to execute it. The [collection-scope contract](contracts/collection-scope.schema.json) is a protected resolved DTO, never a user-writable Kubernetes resource.

## REQ-EXE-001 — Separate immutable scopes

Store three identities:

1. **Submission digest:** the complete authored spec, authenticated actor and source object UID/generation (or browser/MCP request identity). It preserves exactly what was submitted, including sharing, resultAccess, pause and explicit grant handle. Mutating any authored field needs fresh authenticated acceptance.
2. **Collection execution digest:** the resolved collection-scope/v1 record. Include source cluster/namespace/workload or capture/policy UIDs, executor identity, resolved team policy authority when applicable, pod selection, observation/evaluation, detectors, action/recipe/preset digests, budgets, effective retention/local ceilings, endpoint/runtime/image constraints and resolved dependencies. Policy generation itself is provenance, not scope: unchanged execution scope can retain approval across a label, pause, sharing or grant-reference revision. The source policy UID remains bound. Ad hoc scope binds one capture UID and original deadline, so a second request cannot reuse its approval.
3. **Sharing scope digest:** the immutable resolved SharingIntent spec, including exact collection execution digest, creator, management assignments, recipients, projections, counts and expiry. Sharing acceptance and raw-sharing approval never authorize collection. Editing only sharing creates/drains the appropriate sharing revision without forcing a new dump approval; it cannot move already registered captures into a different instruction.

For DebugPolicy, `policyAuthority` is mandatory and pins installation identity, delegation UID/generation/digest, exact sponsoring assignment IDs, original issue/expiry and finite execution/output/observation limits. Its executor is the derived policy principal; the human author remains in authenticated submission provenance. DebugCapture forbids this field. Changing or renewing authority changes scope and needs fresh acceptance/applicable review; no renewal by login, reapply, restart or retry. Existing human-bound scopes are not upgraded in place. See [team policy automation](policy-automation.md).

Exclude grantRef, sharing, resultAccess, suspended, free-text reason and idempotencyKey from the collection spec. Their authenticated submission/control records remain authoritative separately. Grant attachment must compare the current grant target/digest and is audited; it cannot modify the frozen plan. Pausing cancels future starts immediately. Resuming the same scope rechecks current authority, capacity and unexpired approval; it is neither a new approval nor budget reset. Changing target, executor, recipe, trigger, runtime pack, image restriction, observation scope, limits or effective privacy ceiling requires a newly accepted scope and applicable review. Do not infer safety of arbitrary “narrower” edits. Emergency deny/retention tightening takes effect immediately, even while reapproval is pending.

Resolve referenced configuration before hashing; never hash only mutable names. Canonical scope/v1 uses UTF-8 JSON, lexically sorted object keys, no insignificant whitespace, integer bytes/counts, canonical duration units and UTC timestamps. Preserve ordered argv/DAG/sequence lists; sort set-valued fields by their documented identity and reject duplicates. Numbers outside portable exact-integer range or ambiguous normalization fail. Production Go/controller/admission and client compatibility fixtures must agree byte-for-byte. The Python validator checks explicit synthetic scopes and excluded-field behavior, not every future Kubernetes quantity/default normalization.

collectionProvenance.planDigest and SharingIntent.source.planDigest mean this collection execution digest. collector.policyDigest, where present, remains the authored policy provenance digest; it is not the action grant matching key. Keep both names unambiguous in API documentation. Normal UI/GitOps/MCP paths never ask a user to compute a hash.

The initial Kubernetes policy-source adapter supplies a distinct **source collection-intent digest**, not the resolved execution digest above. It validates the complete authored policy against the offline canonical schema, excludes only the named control fields, normalizes omitted `recordingSaves` to disabled and retains every other collection field and ordered list. JSON key order and numeric spelling use RFC 8785; fractional resource thresholds remain supported. Equivalent duration strings or reordered set declarations may conservatively invalidate intent until the full compiler normalizes them. The persisted monotonic intent version fences observed changes and missed spec generations, including change-and-revert. A current source observation alone never accepts execution or revives an approval. The compiler/signature acceptance boundary remains mandatory.

The initial post-persistence policy signature profile now supplies that signature boundary through [ADR-062](../docs/decisions/062-policy-submission-signatures.md). Its private versioned intent binds authenticated actor, complete source revision, independently resolved scope, installation/recovery identity and original nonce/deadlines. The submission envelope digest covers canonical payload bytes, so rotating the signing key cannot manufacture a distinct submission or reset idempotency. Refreshable verification provenance is excluded from the immutable acceptance request digest. No caller-authored envelope can supply its own expected identity or compiler facts. Complete policy compilation, origin admission and public operation composition remain required.

Implemented compilers additionally emit `effectiveRetention`, sorted by action ID, with each action's resolved purpose, privacy class/type, requested age, maximum age, deletion budget and complete policy UID/generation/digest references sorted by UID. These values participate in execution identity: policy replacement or changed resolved limits cannot reuse approval because a dependency definition stayed unchanged. The initial context compiler requires this field for its exact profile; earlier illustrative scopes without it are not accepted product execution inputs. Manual recipe and composed captures support the same optional `retention` request as presets. Normalize omission through current defaults and serialize whole seconds. The protected `collector` dependency pins the qualified collector image separately from diagnostic runtime packs. See [context admission](../docs/architecture/context-admission.md).

### SC-EXE-001

Given an approved policy, when its eligible grant handle is renewed or only recipients change, then the collection execution digest stays fixed while submission/sharing identities change. Adding a core, another target or a broader ceiling changes collection scope and invalidates its approval. A manual capture with no policy can request approval for its own immutable capture identity, which cannot authorize another capture.

## REQ-EXE-002 — Acceptance, deadlines and progress

For the fixed API pod-status execution, require at least one second remaining
before its first irreversible execution-preparation insert, as specified in
[ADR-212](../docs/decisions/212-api-preparation-remaining-interval.md).
Use database time after blocking authority/storage locks and the earlier
original check/caller cutoff. Refusal creates no execution row or key permit;
the accepted capture and its accounting remain unchanged. This conservative
floor does not guarantee completion. A later explicit continuation may become
the first winner under current request-owned authority and unchanged capture
and write deadlines. An exact existing prepared row remains passive no-create
uncertainty after its original expiry; it cannot renew keys, start authority,
charges or the target.

The private regional transport in
[ADR-135](../docs/decisions/135-live-regional-api-context-start.md) preserves the
same accepted API snapshot and original start interval. A connector-originated
standby contains no capture authority. A signed reference stays attached to the
original live human request; disconnect never queues or automatically retries
its work. Under [ADR-171](../docs/decisions/171-hub-run-context-execution.md)
the hub runs the SQL, permission, recovery and capability checks with the
human's own current identity, and the region answers the process, target and
local start checks as bounded operations for the verified work only. All of
them remain mandatory. Under
[ADR-216](../docs/decisions/216-request-owned-context-start-observation.md), one
start reuses one complete hub authority observation within its earliest original
cutoff, at most five seconds. Its pre-signing accepted-work, caller, recovery and
capability reads are reused by the in-process runner. Later helper boundaries
check cancellation and the original observation's validity locally. Current SQL
permission, retention, recovery and storage checks remain mandatory at each
effect, and acquisition still checks the exact pinned Pod. Unobserved external
identity or capability changes may remain unknown within that original interval;
a new start observes them again. No observation crosses requests or renews a
deadline. A transport result is not artifact
publication or a successful download.

The admission receipt's metadata freshness is response-only. Consume its exact
accepted identity while current; do not use that cutoff as authority for the
subsequent independently checked start. Preserve the original caller/identity,
persisted audit first-write, capture, write and execution deadlines. If receipt
metadata expires during a successful start, one current exact-key read-only
lookup may supply response metadata for the identical accepted operation. It
must not read a replacement capture, extend stored dates, repeat admission or
retry any effect. A failed lookup returns an error with the known admission;
ordinary accepted replay remains passive.

Before any capture exists, preview and request target resolution use pre-work
target queries on an idle standby under
[ADR-179](../docs/decisions/179-outbound-only-first-installed-profile.md). The
region answers while it still waits for work, from its own cluster, after a
current check of the hub owner. The hub uses an answer only while the region
receiver checked for that query remains valid. A query executes no operation
and confers no capture authority. Each exchange answers at most four queries.
A query that finds no usable standby withdraws idle standbys that have spent
that budget, so the region opens a fresh exchange instead of holding the
cluster's reservation for the rest of its residency; nothing is refunded.
Under [ADR-211](../docs/decisions/211-completed-query-standby-transition.md), a
fully matched and completed hub query may return its socket deadlines to the
original passive standby cutoff after joining its I/O callbacks. Its result
retains the original target/receiver freshness. Queries exclusively reserve
their standby until completion; capture attachment cannot interleave source
reads. Failed, cancelled, expired or uncertain exchanges never regain time,
and an attempted work lease permanently excludes this passive transition.

The private API context exchange may reuse one complete exact transport peer
observation for ordered regional operation request/response frames under
[ADR-163](../docs/decisions/163-original-work-transport-observation-lease.md). Its
original start, earliest deadline and immutable channel remain fixed; setup or
standby observations cannot authorize work. Final result transfer requires a
full current peer check clipped to that original interval. Cancellation, expiry
and known negative checks terminate without refreshing or replaying accepted
work. This transport-only bounded freshness does not cache human identities or
replace any current application effect/permission/process check. Unobserved
remote revocation can remain unknown only within the original at-most-five-second
transport interval; no instantaneous distributed revocation is claimed.

Within one verified work, the region reuses that work's single complete
executor process observation for its later process reads and start checks
until the observation's original deadline, under
[ADR-173](../docs/decisions/173-work-scoped-process-observation.md). It is
never renewed and never crosses works. The capacity account, start guard and
CapacityReservation CAS checks remain current on every start operation, and
both admission guards enforce every start write. Unobserved changes to the
executor workload can therefore remain unknown for at most five seconds after
that observation began.

A concrete executor may return the connector observation already checked by
its complete native proof to the context-start transport. It must require the
same process-owned credentials instance, retain both original intervals and
return independently owned public buffers. This avoids a duplicate outer
connector observation without replacing any proof, extending freshness or
changing the later setup/work checks. A different credentials owner cannot
borrow the result; process readers without that concrete composition retain
independent observations.

Within that same complete native proof, the explicit source bracket may also
supply the nested read-only registration lookup's two source replies under
[ADR-207](../docs/decisions/207-context-setup-proof-bracket.md). The temporary
reader is bound to one exact known leaf/process and original interval, copies
public buffers, refuses all lifecycle/configuration work and closes after that
conversation. Current SQL registration/recovery checks and the enclosing full
native closing source check remain mandatory; this is no ambient source cache.

The same concrete executor may lend one complete native proof to one private
context-start setup. The original proof generation and exact owned credentials
remain binding through the earliest original discovery, setup, proof and caller
cutoffs. A single initial source frame may use that proof's actual closing source
with original dates. After HTTP response headers and Hello delivery, a current
native workload/settings/input and full source close is mandatory. Both remote
owner authentications remain current; a final local credential/generation check
follows the second. Close cancels and joins owned work before a positive opening
returns. The setup handle is never reused by later exchange checks, target
queries or accepted work. Any failure, known change, cancellation or expiry
refuses the opening without a stale fallback or renewed interval.

Private context-start opening diagnostics distinguish discovery, initial setup
and local process, TLS/peer, first owner, source frame, headers/Hello, native
Finish, closing owner/local process and joined close. A failed cold setup may
also identify its fixed source/proof/settings/workload stage. Only closed codes,
elapsed wall time and time remaining to the earliest already learned original
cutoff are reported after existing cleanup joins. These values are diagnostics,
never authority; cancellation and original error classification are unchanged.
Dependency text, identities, credentials and payloads are excluded. Numeric
timings are outside the finite exponentially suppressed event-count key. This
adds no read, retry, timeout renewal, result field or acceptance capability.

For the initial regional Kubernetes API snapshot, `apiContextStart/v1` binds the
protected executor Pod/account/process and exact collector image, without target
node/boot claims. One immutable SQL execution row and the original Kubernetes
UID/CAS precede capture; only an acknowledged first preparation may create the
local record. Unknown replies and process restarts do not renew the original
request interval or permit another effect. Completed acquisition provenance and
exact ciphertext receipts allow independent verification/publication after the
observed Pod disappears. The existing encrypted verification audit binds this
result; progress and stored bytes alone remain nonauthorizing. Each installation
control namespace has its own start admission match plus independent namespace
UID checks. See [ADR-106](../docs/decisions/106-regional-api-context-start.md).


Allocate an opaque capture identity before preparing an intrusive approval request. Resolve and freeze the plan, current pod set, per-action fanout/ceilings, privacy and original deadline. The protected collection-scope/v1 record for DebugCapture MUST contain podBindings: a nonempty list sorted by podUID, unique by podUID and bounded by target.maxPods. Cluster and namespace identity come from source. Each binding uses the execution class selected by protected capability, never a caller option. The historical node class omits executionClass and requires podUID, nodeUID and nodeBootID; it resolves only scheduled, currently authorized pods. A replacement pod, rescheduling or node boot invalidates that node-bound manual start. The explicitly qualified kubernetesAPI class is currently limited to one builtin-pod-status-v1 snapshot: its binding contains podUID and executionClass, forbids nodeUID/nodeBootID and permits an unscheduled Pod. It binds the exact namespace, workload owner chain and Pod incarnation; replacement still invalidates start, while scheduling the same Pod does not. No missing node identity implies API fallback. The class participates in execution identity and in the independently verified manifest. Neither class permits an empty approval that fills itself later. DebugPolicy has no fixed podBindings: its authorized observation/selection rules follow current replicas, and each incident/permit pins its admitted concrete pods. These are internal identity fields, not new container-level configuration. A matchedProcesses plan binds its logical selector and permits fresh process resolution within those pinned pods immediately before dispatch under REQ-ACT-008; selectedPID binds the exact process from acceptance. Pending approval is a per-action condition. Run independent permitted context within its own reservations; reserve expensive impact/storage only close enough to dispatch to avoid holding scarce capacity during a human's review. Approval does not reserve indefinite node/storage service. Each process-affecting child start uses the same parent's aggregate bounds and its own deduplicated attempt/reservation.

Before starting, revalidate identity, authority, current grant, source freshness and capacity. If the pinned process is gone or the request deadline passed, do not start against a replacement or extend the request. Offer an explicit fresh capture while keeping old context and denial details. Cancellation is idempotent, blocks unstarted work and requests safe cancellation of active work; Indeterminate remains possible. Deleting a CRD is not evidence deletion, nor automatic sharing revocation.

A summary phase is a projection of action states: Running while any action runs, AwaitingApproval only when no runnable action is active and some remain eligible pending review, Finalizing after acquisition ends. Terminate Succeeded only when every required action succeeds; Partial when useful artifacts exist with missing/failed work; Failed when required evidence failed without usable output. Report cancellation and uncertain execution explicitly. No successful artifact is hidden by a waiting optional action.

### SC-EXE-002

Given an accepted API context capture with no execution preparation, hold a
required SQL lock until fewer than one second remains in its original
check/caller interval. Preparation must refuse with no execution row or key
permit. An explicit fresh continuation for the same accepted identity can
then produce only one first-preparation winner. Given an existing exact
prepared row whose start interval has expired, current-authorized replay must
retain its original binding and produce no-create preparation uncertainty,
without another key effect, start or acquisition.

Given cheap context and a required intrusive action, when approval takes longer than the capture deadline, then context runs once and becomes visible immediately, the intrusive start never occurs and the terminal result explains partial evidence. A refreshed page or repeated MCP request returns the same capture without resetting its clock or counters.

## Repeating a retained request

REQ-HIS-001–004 in [capture history](capture-history.md) define restoration from an authorized immutable settings snapshot. Repeat lineage is a non-authorizing source reference; each accepted repeat binds its own capture UID, requester, deadlines, current dependencies and collection digest. A client retry of that operation is still deduplicated. No old grant, sharing instruction or prepaid capacity is copied. A missing source snapshot cannot be reconstructed by executing its current namesake recipe. History publication is a bounded optional projection; failure to record history does not duplicate or cancel an accepted acquisition.

## Composed capture identity

For profileComposition, retain authenticated authored components/edits, immutable resolved definitions, expanded recipe and action alias map. Include each CaptureProfile as a captureProfile dependency with source cluster/object UID and definition digest, plus every transitive endpoint/engine/projection dependency. The expanded recipe digest is authoritative for actual actions and SharingIntent recipeDigest even without a user recipeRef. Availability revisions are current start checks, not changes to immutable definitions. Disabling, deleting or replacing a source cannot be bypassed with an accepted preview, old history or stale catalog cache; use the normal connected revocation/disconnected permit bounds.

Compilation is deterministic under [capture profiles](capture-profiles.md). Initial combined bounds and inferred values are previewed before acceptance; user edits, profile upgrades or materialized customization create a new collection scope. Captures/policies and repeat requests execute through the existing admission/permit state machines.

The protected collection-scope/v1 DTO records composition provenance in its top-level profileComposition field; collection.spec uses the normalized expanded recipeRef with a service-owned `composition-<24 digest characters>` name and the complete expanded recipe digest. That internal name does not require a public EvidenceRecipe object or caller publication rights. Every captureProfile dependency carries source cluster/namespace/object identity in addition to the immutable definition digest. The dependency set must exactly cover the resolved profiles; source replacement changes scope even if recipe bytes match. Authored CRDs keep their original profileComposition form.

## Source sessions and incident execution

Normalize each action's executionMode using the immutable contract-version defaults in [action lifecycles](action-lifecycle.md). Persist resolved modes in accepted plans and their digests. Authored recipe/profile digests still identify their exact input; compiled effective-plan identity additionally binds default resolution. Explicit mode changes cannot reuse approval by claiming a harmless scheduling edit. Split ongoing-source activation from the incident graph; dependencies on an ongoing action refer to this incident's output, never to terminating its source.

Service-owned sourceSessionID/epoch identifies one authorized recorder and its reservations. Each incident owns separate snapshotID/action attempts and a t0-anchored window. Source leases/readiness and incident action timeout/completion are separate state machines. Retrying an incident references its original snapshot and does not attach another source. A manual capture owns a finite source session; cancelling its capture stops that session, whereas cancelling a policy incident stops only that save. No accepted history record reactivates an old source identity.

## Assessment identity and current checks

[Capture assessments](capture-assessment.md) bind the resolved execution digest, rule/capability digests and a short freshness interval. Keep the assessment ID and content-minimized warning basis with acceptance and approval review; a report is not an execution permit. Do not hash changing metrics/timestamps into the collection grant scope or demand policy renewal on every measurement. A material new interactive warning refreshes the preview; changed collection/retention scope follows ordinary acceptance and review. Before arming/dispatch, recheck current rules, authority, capacity and runtime headroom regardless of what an earlier preview said. Idempotent retries of an accepted operation return that operation, without reacquiring or manufacturing a new consent step.

## Recording-save execution identity

[REQ-SAV-001–004](recording-saves.md) define a separate protected recording-save/v1 scope rather than disguising a subset as collection-scope/v1 or reusing a full-recipe grant. `recordingSaves.enabled` is collection-affecting policy configuration and participates in policy digests/review. Its omission normalizes to false; the fixture projection preserves authored omission while production canonicalization explicitly resolves that default. Enabling it never retroactively authorizes old source sessions.

Allocate the save's capture UID at preview, bind exact source/pod/node/boot/action/definition identities, source audiences, requested lookbacks, requester, unchanged policy executor, limits and dependency pins. Sort sources by sourceSessionID, reject duplicates by that ID and by podUID/actionID, and limit selected distinct pods to the policy's incident cap. The canonical save-scope digest becomes collectionProvenance.planDigest and the per-capture sharing source digest. The existing policy execution digest remains separate provenance/authority; it cannot be substituted for the save digest. Persist t0 and deadline once in the signed accepted execution, bind them to the scope/capture identity, and preserve them on every idempotent retry. Only this typed operation may consume a reviewed policy save permit; ordinary ad hoc actions retain individual approval.

Preview operation kinds are service-owned and disjoint. request_capture must dispatch a recording-save preview only to the snapshot executor and a collection preview only to the ordinary executor. Current authority, source identity, retained audience, effective privacy/capacity and save enablement are rechecked before pinning; changing any material selection/configuration needs a fresh preview. Metadata-only policy revisions do not change the accepted execution digest by themselves. No creator/initiator field widens source evidence access.

## Result access bound to a capture

[Investigation approval](investigation-approval.md) adds a separate canonical resultAccess digest over `{captureUID, executionDigest, resultAccess}` (the latter excludes its own digest). Canonical serialization follows the existing scope rules. The human review scope includes both collection and result-access digests. A result-access edit requires a fresh approval; it neither mutates the collection execution digest nor restarts acquisition. The accepted request protects the authored instruction, and only the authorization component writes resolved scopes/child resultOrigin. A query cannot replace a parent by another capture with an identical recipe. Existing collectionProvenance.planDigest keeps its original meaning.
