# Regional Kubernetes API context

This C-06/C-11/C-14/C-21 segment implements the execution-class distinction in
[ADR-104](../decisions/104-regional-api-context-execution.md) under REQ-EXE-002,
REQ-EVD-001–003 and the S-02 context workflow. It allows the fixed Pod status
snapshot to inspect a Pod that has not been scheduled. It does not enable a
public collector or complete regional execution/start authority.

[ADR-216](../decisions/216-request-owned-context-start-observation.md) gives one
start one complete hub authority observation within its earliest original cutoff,
at most five seconds. The hub's pre-signing accepted-work/caller/recovery/capability
reads feed the runner directly. Target, eligibility, retention and process are
resolved once before preparation; later helper boundaries validate the retained
observation and cancellation locally. SQL still checks current permission,
retention, recovery and storage under its effect locks, and acquisition still
checks the exact pinned Pod. No observation crosses a request or renews a deadline.
Implementation and installed qualification are tracked in the progress record.

The first durable execution preparation follows
[ADR-212](../decisions/212-api-preparation-remaining-interval.md): after current
authority and storage locks, database time must leave at least one second
within the earlier checked/caller cutoff before insertion. This is a
conservative availability rule, not a new deadline or performance guarantee.
Refusal leaves no execution row or key permission. Exact existing prepared
rows are passive no-create results even after expiry, allowing the runner's
existing `PreparationUncertain` classification without repeating effects.

[ADR-217](../decisions/217-api-execution-role.md) composes the hub's read,
preparation and recording ports with one `APIContextExecutions` adapter, one
`api-execution` SQL credential and one cold three-connection pool. The exact
former grant union and existing SQL methods are retained. This does not join
regional acquisition, audit, publication, key-service or deletion credentials.
The hub physical connection governor remains 32.

## Lost regional replies

[ADR-223](../decisions/223-lost-regional-completion-reply.md): when the region
has committed its copies but the acquisition or `CompleteStored` reply does not
reach the hub, SQL keeps `started` and the hub does not import the artifact.
Retries return `AlreadyStarted`; collection is never repeated. Progress reports
Running until the hub-worker deadline observer marks the original deadline, then
Indeterminate/DeadlineOutcomeUnconfirmed. The storage charge stays held until
the normal deletion lifecycle releases it. A `prepared` row without a recorded
start reports Pending/DispatchUnconfirmed.

## Exact class and target

`artifact.ContextExecutionClass` has two supported values. The empty value is
the existing node class and stays omitted in historical JSON. `kubernetesAPI`
is explicit and server-selected. It is not a user choice or inferred from
missing node fields.

The API class is carried by `targets.PodResolution`,
`planning.ContextCapability`, `capture.ContextPreview` and
`artifact.ContextExpectation`. The compiler requires exact target/capability
agreement. API targets and previews forbid `Pin.NodeName`; API targets and
expectations forbid node UID/boot. The node class retains all previous
requirements. Class changes are consequential reviewed-scope changes.

`NewAPIContextTargets` constructs the read-only resolver in its fixed API mode.
A named Deployment/StatefulSet selects the lexically first nonterminating,
actually owned Pod from a complete bounded candidate list. It retains the
existing 256-candidate limit; an incomplete or oversized list is unavailable.
An explicitly selected Pod normalizes to its actual supported workload owner.
API selection includes unscheduled Pods. No eligible Pod is distinct from a
node class having no eligible scheduled Pod.

Resolution rechecks the exact Pod, owner chain and namespace within the
original five-second observation interval and original caller deadline. It
never reads Nodes. API assignment changes do not alter a pin or claim authority
on the assigned node. Deletion, replacement, owner change, missing permission,
timeout or cancellation cannot yield a substitute target. Current workload
eligibility still precedes public target disclosure.

## Scope, manifest and collection

API `collection-scope/v1` pod bindings include `executionClass: kubernetesAPI`
and `podUID`, with no node/boot fields. The schema limits this class to the
single-Pod `builtin-pod-status-v1` profile. Historical node bindings retain
their exact canonical bytes; their existing independently checked fixture
continues to apply. Resource-version and observation freshness still do not
become approval identity or renew acceptance deadlines.

`NewAPIContextClient` uses the same bounded secure Kubernetes transport and
fixed status projection as the existing node collector. It checks namespace,
Pod and controller identity. `scheduled` remains an observed finite condition;
the native projection exposes no node name, workload configuration, labels,
annotations, addresses, environment or free-text messages. It makes only
namespace and Pod reads, with at most five seconds and a 2 MiB response ceiling.
The complete projected output remains at most 4096 bytes.

The accepted API expectation requires metadata, `pod-status` and the exact
4096-byte native allocation ceiling. Its encrypted manifest includes
`target.executionClass: kubernetesAPI`; the canonical schema forbids node/boot
claims and restricts kind, format, action and native size. Verification compares
that class to independently accepted facts before native-byte validation.
Removing the class cannot produce a valid historical node manifest, and adding
node facts cannot turn an API artifact into node-attested evidence. Existing
encryption framing, AAD, wrap-only producer, copy reservations, verification,
retention and native read mechanisms are reused unchanged.

## Verification and remaining composition

Focused tests cover unscheduled selection, scheduling during resolution,
actual-owner normalization, replacement/owner changes, forbidden API calls,
original deadlines/cancellation, class mismatch, historical scope bytes and
manifest/class substitution. The native extension is
`TestContextCommitWithRealServices/unscheduled-api-context`: a separate real
service account has only namespace/Pod/owner reads; actual Node and exec calls
must be denied. The fixture creates a Restricted unscheduled Deployment,
resolves and compiles its exact Pod, collects it, prepares encrypted
data/index/manifest/envelope, verifies into SQL `stored_unpublished` custody and
recovers the exact native bytes. Capability, human/audience, retention and
initial capacity remain synthetic fixture control inputs. The SQL admission
fixture independently exercises accepted API-class expectation and replay.

The native fixture is not reported as passed by its presence in source. Parent
qualification runs the owned external suites only after a coordinated source
freeze and records terminal exits, cleanup and source hashes in implementation
progress. Focused compile/race results and any observed corrections are retained
there separately.

Next connect the regional executor to the existing exact prepaid start journal,
intent audit and publication path using distinct capacity and execution
identities. A node receiver/boot pin must not be fabricated for that route.
Unknown starts remain spent and replay never reacquires evidence. Current
eligibility, retention, recovery, writer exclusion and independently verified
provenance remain mandatory. Artifact access after acquisition must not depend
on the workload Pod or collector process still existing. This segment adds no
new installation knobs, public runtime endpoint or permission evaluator.
