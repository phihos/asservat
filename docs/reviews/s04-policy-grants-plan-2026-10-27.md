# Policy grants and prepaid sensitive observation

Status: architecture decisions accepted by maintainer through the root coordinator; implementation in progress. Scoped component qualifications below do not establish installed completion.
Scope: S-04 increment 12b, REQ-AUT-003/004/006, SC-AUT-003/004/006,
REQ-EXE-001 and the accepted team-policy authority contract. ADR-259 and migration
00102 follows packet funding 00100 and history 00101. Local composition
`822e79b5` now includes the reviewed history cc2 and approved-recording 218 source;
SQL implementation on that local schema 101 base is authorized. Canonical PR100/main
composition remains required before publication or an installed campaign. PR100
supplies no policy-grant qualification.

## Observed boundary

- `authorization.Grant` and migration 00097 support only `adHocCapture`. They
  require capture/preview/Pod identifiers and bind later use to the human requester.
  Reusing those requirements with invented policy identifiers would be wrong.
- Existing C-09 activation already stores an independently bounded policy executor,
  delegation and sponsoring assignment set. The current implementation admits only
  pod-status recipes. Its preflight constructs `PodUID=WorkloadUID` and temporary
  positive limits to select the envelope; these must not become a grant scope.
- The current recorder compiler binds raw-predicate observation limits: 1 GiB,
  16 MiB/s, one concurrent session, session seconds from the action timeout capped
  at one hour. These are configured ceilings, not measured load.
- `recorder_approval.go` deliberately refuses every approved plan that has those
  limits. Keep that refusal until actual quota enforcement precedes the predicate.
- `packets.Recorder.Add` currently filters before its `WireBytes` increment, and
  that counter describes retained frames only. It cannot meter sensitive input.
- Published Gadget delivery already provides original `packet_size` separately
  from captured payload bytes. The new gate belongs before `rec.Add`, without
  changing the gadget or introducing a packet parser/kernel program.
- Row 6 of [the S-04 plan](s04-plan-2026-10-27.md) owns ongoing policy source/ring
  arming. A policy grant alone must not pretend that arming is implemented.

## Complete first supported workflow

1. A maintainer authors a schema-valid hub-held DebugPolicy with an explicit
   `onTrigger`, `before: 0s` packet composition and finite incident limits. Extend
   the existing compiler for that supported path; retain the field-specific refusal
   for ongoing policy recordings until increment 6. The grant scope is still the
   pinned workload and its authorized future replicas, never one selected Pod.
2. Activation resolves the real namespace/workload, source, delegation, sponsors,
   compiled recipe/filter programs and policy authority. It accepts that exact
   team scope through existing C-09 persistence/audit. Missing sensitive approval
   blocks acquisition; it does not substitute a pod-status capture.
3. The authenticated human/service requests a policy grant for that accepted
   scope, with finite executions, output bytes, observation bytes/events, rate,
   concurrent sessions and expiry within the resolved ceilings. Keep the original
   requester as provenance, separate from `policyExecutor` and `policyAuthority`.
4. A different current human action-approver reviews the exact workload, recipe,
   predicates, authority, budgets and expiry, then uses actual IdP step-up to decide.
   Self-approval compares issuer/subject with the authenticated requester across
   clients, never with the machine policy executor. Workload identities cannot decide.
5. A current team manager attaches the exact approved grant using the existing
   activation/control path. Prefer this explicit action over a new grant-head
   service, automatic newest-grant selection or a cross-role background update.
   Use optional grant_id on activate_policy: an authored grantRef must match
   exactly; absent grantRef permits an explicit runtime attachment, while changing
   an authored reference stops reuse until reconciliation. The immutable SQL control
   receipt is semantic/idempotency state, not durable object audit. Existing public
   activation acknowledges encrypted intent before attachment and records outcome;
   unknown replies/replay preserve the exact attachment. No new audit worker.
   Renewal can be reviewed while the old grant remains attached; attachment does
   not reissue the policy authority or reset any policy counters.
6. On a real incident, the existing policy occurrence executor resolves and checks
   the actual triggering Pod. Admission atomically reserves ordinary capacity and
   grant executions/output/observation credit, with current authority and deadlines.
   The public requester's token or group snapshot is never retained for execution.
7. The connector sends only the admitted command and finite prepaid observation
   lease over the existing authenticated node channel. The node charges every
   original wire byte before evaluating the approved predicate, including frames
   the predicate discards. No byte is processed without live authority and credit.
8. Publication/native download use the existing custody and current-rights paths.
   Policy approval grants no personal resultAccess, raw-query, download or sharing
   right. Inspection still uses the viewer's independent current rights.
9. Exhaustion/revocation/expiry stops sensitive reads and new starts. Independently
   authorized cheap detectors remain usable. A new node/process, pause/resume,
   grantRef edit or repeated request cannot refill either the grant or policy pool.

This is an actual automatic sensitive-packet workflow, including UI and installed
proof. It is not a completed ring/source implementation, HTTP parser, raw output
mode or syscall argument acquisition. Those later mechanisms must consume the
same accounting boundary before being enabled.

## Scope, storage and authority

Use a discriminated grant scope. Keep existing ad hoc validation unchanged.
`policy` requires real policy UID, policy execution digest, executor and exact
policyAuthority (including original issue/expiry and sponsors); capture UID,
preview ID, Pod UID and resultAccess are forbidden. Workload identity consists of
cluster/namespace/workload UIDs. Review names are metadata, not authority.

Add a purpose-specific workload eligibility type/port. Do not relax
`authorization.Target.Valid()` for artifact reads or replace a Pod UID with a
workload UID. Share the existing assignment evaluation and accepted source reads;
perform concrete per-Pod checks again for each incident/source effect.

Factor the recorder recipe/filter compilation used by manual and policy plans;
attach the appropriate owner/target scope afterward. Do not call a manual compiler
with `CaptureID=PolicyUID`. Frozen programs/provenance must agree with the reviewed
policy digest before execution. A source/recipe/authority change requires fresh
acceptance and applicable review; runtime freshness stays outside approval identity.

Extend the purpose-owned grant ledger where common decision/revocation/audit
rules apply, with conditional NULLs for irrelevant target columns. Keep policy
admission and observation facets narrow. Reuse existing SQL duties; any SECURITY
DEFINER helper is fixed-purpose, schema-qualified and EXECUTE-only for its actual
consumer, with the installer role matrix and reversible migration checked.
Policy aggregate spend must also survive grant replacement: a new grant does not
reset the accepted authority's cumulative ceilings.

For policy grants, requester identity is provenance, not perpetual control.
Current team managers/current approvers control attachment and revocation; creator
logout, departure or personal client removal does not revoke independent team
execution. Ad hoc requester behavior is unchanged. Restrict PR100 preview
resume/resolve/original-client hints explicitly to ad hoc grants when adding the
new kind; policy grants get no invented preview or personal continuation action.

## Lifetime and current settings

Reuse the protected installation settings/cache and canonical
[approval-policy fields](../../specs/contracts/approval-policy.schema.json), not a
new watcher, provider credential or configuration service. Proposed initial values
match the existing example: seven-day default, thirty-day maximum, one-day renewal
notice; the configurable upper bound remains 365 days. These defaults are an
implementation choice, not an additional maintainer requirement.

Policy grant `issuedAt` is the immutable original request/issuance time, distinct
from the decision and policyAuthority issue time. Requested notAfter is fixed
there. Approval clamps it to the current effective maximum from that same original
issue time and the original authority expiry. Persist a monotonic effective
expiry overlay; raising a maximum never extends a stored grant. Every new
reservation/lease renewal uses current accepted settings and rechecks after locks.
Sharing/raw-query maxima stay separate. Renewal is an explicit reviewed new grant,
never a timer that changes the original grant or policy authority.

Reuse the existing protected accepted-settings observation model (currently
30 seconds), not raw ConfigMap history. Persist each accepted lower maximum so
all earlier-issued grants clamp irreversibly from their original issuedAt even
when unused during the lower period. Reuse source identity/epoch/audit acceptance;
benign resourceVersion changes do not revoke grants. A raw change-and-revert that
was never accepted is not claimed as processed. This is the maintainer-approved
bounded-observation contract; no new watch/history service is authorized.

## Observation constraint proposal

Maintain separate authoritative reserved/spent counters for executions, output,
observed bytes and optional observed events. Actual node-observed input is a
separate quantity from the conservative hub reservation. Existing retained
`WireBytes` keeps its meaning.

Piggyback cumulative byte-credit extensions onto the current-authority renewal
required for sensitive policy observation. The present metadata recorder has no
per-capture authority-renewal RPC: status/poll/certificate exchanges are different
purposes. Add one renewal operation on the existing private node channel; count
its entire cost, rather than claiming an already-running renewal stream. Use the original session/fence and idempotent sequence, with one outstanding
RPC. Do not add an independent quota-renewal stream or two-slice state machine.
Keep unconsumed existing credit when the remaining parent pool is zero; an authority
renewal does not require a new debit. Unknown possibly-started credit remains
conservatively spent, with no refund protocol.

Derive the initial/extension quantum from the reviewed maximum rate multiplied by
the bounded authority horizon, provisionally covering two selected renewal intervals.
At 16 MiB/s and a five-second interval this would cover 160 MiB for ten seconds;
a full one-hour prepayment at that rate would request 56.25 GiB, whereas a ten-second
session would request the same 160 MiB. Both are capped by actual remaining policy
and grant budgets. Short/no-traffic sessions may consume the entire prepaid tail;
show conservative spend separately from measured input. Measure actual existing
channel cost plus the eventual SQL renewal transaction and interval before fixing
the quantum. One renewal stream
at five seconds implies 40 requests/s for 200 active sources, rather than the rejected
independent 64 MiB credit stream's approximately 90 requests/s combined.

At the node, use the existing serialized frame callback and original wire length
before any filter. Exhaustion/rate/lease failure cancels capture before another
predicate evaluation; no unchecked fallback. Renewal uses current trusted policy,
grant, source and node identity, is bounded by the original session end and grant
expiry, and never resets byte/event counters. If freshness makes the lease shorter
than the capture, renew it over the existing private channel, retaining those
original bounds. Reused credit can renew authority while its pool has no *new*
credit remaining; renewal must not mistake its own reserved bytes for exhaustion.

One session row can hold the cumulative allocated ceiling and sequence. Bound
active rows by reviewed concurrency and the existing default ceiling of 64.
Finalize/expire reserved credit conservatively, retain aggregate spend, and move
completed receipts to existing immutable audit before bounded retirement. Expiry
may free an authority slot but cannot refund bytes or revive the old session.

The packet rule charges wire bytes, not retained/truncated bytes. Keep an explicit
accounting-rule/adapter digest. Canonical `maxObservedEvents` and its counters are
preserved for future syscall arguments, but no callback after a user-memory read
can qualify the required before-read charge. Keep argument acquisition unavailable
until a published gadget/qualified adapter can enforce that boundary. No custom
kernel/eBPF program or hand-written packet parser is proposed.

Before lifting the raw-predicate guard, qualify captured-prefix/read bounds too:
the current gadget adapter captures at most 1500 bytes while the compiler pins a
65,535-byte filter snapshot. A grant cannot make an unqualified payload-offset
predicate exact. Supported bounded filters must pass actual compiler/engine tests;
unsupported inspection must retain a clear refusal rather than silent false
matches or an unmeasured larger capture buffer.

## Complexity gate

| # | Answer |
|---|---|
| 1 | Observed missing path: every raw predicate stays RecorderUnavailable; policy compiler refuses compositions. Required product feature, not measured incident frequency. Existing WireBytes excludes filtered input. |
| 2 | Accepted: all first-release specification features, independent policy execution, bounded sensitive observation and no refill. No new security requirement. |
| 3 | Applies to every sensitive policy/recorder and admin-required policy approval; ordinary metadata remains unchanged. |
| 4 | Reuse Asservat's existing SQL reservation, current authority and unknown-spend mechanisms. Envoy RLQS documents server quota assignments with TTL and usage reporting; this is precedent for bounded assignment, not a dependency or evidence that its fallback behavior fits Asservat. |
| 5 | Zero collector SQL/KMS/object credentials, extra listener, privileged workload role or custom kernel/parser. Existing hub duties gain narrow grant/slice operations; exact installer privileges need native qualification. |
| 6 | Existing grant phases plus explicit exhaustion/source stop. No automatic approval renewal, best-effort permission fallback or refund state machine. Waiting credit is bounded by the original lease. |
| 7 | Only required approval period and reviewed grant budgets. No watch tuning, retry-disable or collector machinery configuration. Rate-times-authority-horizon credit is internal and must pay for its measured cost. |
| 8 | Existing PostgreSQL/Kubernetes/IdP/Gadget and private TLS channels; upstream before-read support remains a real blocker for syscall arguments, not an assumed capability. |
| 9 | Per packet: local counter/rate/lease checks, no allocation or network call intended; benchmark actual ns/allocations. One required sensitive-authority renewal carries credit too: a hypothetical five-second lease at 200 sources means 40 logical renewals/s, with node→connector and connector→hub RPC legs counted separately and no additional quota-only stream. Measure the current combined path before choosing the rate-times-horizon credit quantum. No added watches. |
| 10 | Additive conditional grant migration with tested Down and no conversion of old scopes. Disable new sensitive activations without disabling cleanup/current metadata. No spent-counter reset on rollback/restart. |
| 11 | Explicit onTrigger policy execution avoids prematurely building ongoing arming/rings. Explicit approved-grant attachment avoids a new grant-head controller. Prepaid slices avoid per-packet hub I/O; conservative tail charging avoids a refund protocol. Do not substitute pod-status or foundation-only tests for the real sensitive workflow. |

[Envoy's primary quota documentation](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/rate_limit_quota_filter)
confirms assignments, TTL and reports. Asservat must deny sensitive processing
without an assignment or after expiry; it does not adopt Envoy's optional fallback
behavior or install Envoy/RLQS.

## Public/UI contract and proof

- Request/attach policy approval through the existing policy workflow and typed
  public operations. Approval detail shows policy/team execution, all future
  budgets, original/effective expiry and independent requester/reviewer. No human
  capture resume or resultAccess is offered for this kind.
- Policy status distinguishes detector monitoring, approval availability and
  acquisition/source readiness. Show reserved/conservatively spent input separately
  from actual reported input and retained output. Source implementation gaps are
  explicit. Renew/attach controls require the current manager, not a historical creator.
- Before production edits, reproduce missing policy-kind/observation behavior in
  meaningful tests. Unit/race: typed target/identity separation, cross-client
  self-review, lifetime clamp/raise/replay, before-predicate charge with zero
  matches, rate/session/concurrency bounds and cancellation/lease renewal.
- SQL/S3: atomic capacity+grant debit, concurrent node/replica spend, duplicate
  reservation/renewal replies, revoked/expired grant and source races after locks,
  original issue/expiry, no grantRef/authority counter refill, roles and Down/Up.
- Native collector: published gadget, positive capture plus a predicate retaining
  zero frames while real wire input exhausts a scaled *publicly reviewed* budget;
  actual authority renewal, no processing after expiry/revocation, node restart
  without refill. No knob that mutates immutable plans or bypasses real authority.
- Installed focus: real Kubernetes policy/source/delegation; public request,
  distinct signed Keycloak step-up reviewer; actual automatic packet occurrence,
  encrypted publication/native PCAPNG, policy budget/status and refusal after
  exhausted/revoked authority. Reuse PR100's real helpers and independently current
  rights. A small reviewed grant is product configuration, not a test-only meter.
- Freeze final sources and run the affected repository/role/custody gates before
  one agreed native campaign. Every job stays within 20 minutes; record actual
  full elapsed time, source hashes and cleanup. No collector runs locally.

Expected files: domain/application authorization grants and automation; C-09
policy compiler/activation/trigger/identity; shared recorder planning and context
admission; purpose SQL queries/migration/role facets; private node/connector work
contracts and packet callback; protected settings DTO/schema/installer/chart input;
policy/approval operations/OpenAPI/MCP/React controls; focused tests and native
fixtures. Coordinate shared history/admission files and generated schema head
before edits. No migration or API behavior is implemented by this proposal.


## Implementation checkpoint (in progress)

The isolated policy-grants branch now has discriminated policy scope validation,
original-issue/pending deadline overlay rules, typed workload permission projection,
request/review/revocation service paths, shared transport composition conversion,
shared profile/filter normalization and inert finite policy recorder compilation.
Existing manual network/syscall scope hashes match the original compiler. A local
serialized input meter charges wire length before predicate dispatch and rejects
credit/rate/lease overrun without changing observed counters on a refusal.
On this local Ryzen 7 5700X3D, the initial provided-timestamp microbenchmark
measured 23.92 ns/frame; the later same-domain sample measured 16.19 ns/frame and
51.76 ns/frame including `time.Now`, all zero bytes/allocations per frame. These
are local synthetic meter costs, not collector throughput or installed overhead.
Channel, SQL and aggregate callback costs still need measurement.

Protected policy-period DTO/schema/reader plumbing preserves absent defaults and
copies the cached value. These changes are not wired into production grant
projection, policy activation/attachment, admission, node renewal or UI yet. The
raw-predicate refusal is retained. No policy-grant migration, hosted test or
installed policy/observation qualification exists at this checkpoint. Continue the
full workflow, including source/acceptance compatibility, SQL and native proofs.

## Accepted settings clamp: measured simpler alternative

Maintainer decision after the numeric comparison: use one indexed set-based
monotonic SQL clamp when accepting a lower effective policy-grant maximum. Do
not add revision history, read-time replay, pruning, paging checkpoints or a
new reconciliation service. Accept the protected settings projection and clamp
all affected pending and approved older grants atomically. Derive every lower
deadline from immutable RequestedAt (the policy grant's original issued anchor);
a later raise never extends that persisted deadline. A failed transaction
publishes neither a new accepted projection nor a partially clamped grant set.
The existing loop may retry the same observation within its original bounds.
Unobserved ConfigMap ABA changes are not claimed as processed.

There is no enforced global grant-row ceiling. The separate specification's
64 value limits concurrent reservations within a grant. One accepted settings
change per day is an explicit workload assumption, not observed deployment data.
The 3,200-row scenario assumes 100 clusters × 16 policies × two grant rows;
pending renewals can exceed it, so it is not a product cap.

The isolated PostgreSQL 18.6 comparison used two CPUs, 768 MiB, 64 MiB shared
buffers, fsync and synchronous_commit enabled, an indexed synthetic table with
256-byte payloads and a simple monotonic trigger. Each scenario had three
paired actual UPDATE samples. Both methods verified pending and approved
original-anchor clamping. Median database execution/commit times:

| Active rows | Expired retained rows | One set UPDATE | 64-row committed pages | Commits/pages |
| --- | --- | --- | --- | --- |
| 64 | 0 | 1.026 ms | 5.362 ms | 1 |
| 3,200 | 0 | 18.917 ms | 197.653 ms | 50 |
| 10,000 | 0 | 61.413 ms | 641.941 ms | 157 |
| 100,000 | 0 | 786.484 ms | 7,132.902 ms | 1,563 |
| 64 | 100,000 | 2.024 ms | 12.938 ms | 1 |

The 100,000-row set samples ranged 728.534–1,885.476 ms. PostgreSQL chose a
sequential scan when all rows matched, and an index scan for 64 live among
100,000 expired rows. At an assumed one page per existing one-second loop,
1,563 pages would require about 26 minutes; that cadence was calculated, not
slept through. Docker command/setup time is excluded from database times and
is retained separately in the report. These measurements cover synthetic SQL
only, not the final grant schema, lock contention or a production scale claim.
At the assumed one change/day, the measured set cost does not justify the extra
history/read path or a partially applied clamp state. Existing bounded operation
and transaction deadlines still apply; beyond the measured bound, failure must
leave acceptance unchanged rather than inventing an unbounded grant-row cap.

Corrected benchmark exit 0 in 67.629 seconds, all 15 paired samples, no cleanup
failures; owned container and volume independently absent. Report SHA-256
`3eeee0bd2eb578b7ee9ecfdfb20493999e0a2ea7a88dab26bfbb009b969922c7`.
Two prior attempts failed (non-keyset page cost and temporary-init-server
readiness) and are retained separately; they are not successful measurements.


## Original-request replay and settings supervision

A policy-grant request first performs one indexed lookup in the existing immutable
request row, scoped to the full authenticated actor (issuer, subject, client and
kind), idempotency key and canonical caller-input digest. The digest includes the
original explicit lifetime choice, including zero for the then-current default,
and reviewed budgets. An acknowledged retry returns the frozen request even if
current defaults change or the plan reader is unavailable; it never creates a new
grant, extends a deadline or refills spend. Changed caller choices conflict.
Current workload rights and final identity bounds precede returning metadata.
The immutable scope also stores the original approval maximum alongside its
settings revision, binding it and the resolved recipe digest in the review digest. Public maxAgeSeconds can be
rendered from that frozen value without settings history; later lower maxima
remain a separate monotonic deadline overlay. The persisted accepted lower-maximum
overlay still applies on replay. No table,
credential, public operation or additional background work is added for recovery.

The maintainer accepted one joined child of the existing permission worker for
settings observations, using its existing protected identity client/credential.
The ten-second cache-driven cadence adds at most 0.3 Kubernetes GET/s per
installation (the existing three-source proof), not per workload, and one SQL
acceptance per new cached observation (about ten seconds), plus the measured
set-based clamp only for accepted lower changes. Cached source reads retain their
original timestamps. The client releases its lock during API work, shares pending
refreshes and serves valid cached observations without waiting for a pending
refresh outside its existing safety margin. No watcher, configuration or separate
client is added. A bounded source/SQL failure only expires policy-grant availability;
it cannot stop permission/browser loops. Parent cancellation joins the observer's
original bounded request. This observer and SQL effects remain unwired until the
00100/00101/00102 schema sequence is composed and qualified.


Static Gadget review confirms the pinned tcpdump config exposes `snaplen` as a
maximum-byte parameter; v0.57.0 source declares a uint16 constant with default 1500
and appends packet bytes through perf-event context output, rather than a fixed
1500-byte packet array. That parameter type is not proof that 65535 is usable:
Linux perf record headers have a 16-bit total size including event metadata and
alignment. The current adapter's 1500 guard therefore remains while effective
published sample bounds and compiler byte-access assumptions are investigated.
Sources: [published v0.57.0 program](https://github.com/inspektor-gadget/inspektor-gadget/blob/v0.57.0/gadgets/tcpdump/program.bpf.c),
[Linux perf record layout](https://github.com/torvalds/linux/blob/v6.18/include/uapi/linux/perf_event.h),
and [perf output implementation](https://github.com/torvalds/linux/blob/v6.18/kernel/events/core.c).
This is source evidence, not a native jumbo-packet qualification or a new product
restriction. No Gadget program or host kernel is changed for this investigation.


### Pending SQL 00102 replay compatibility check

The current 00097 request uniqueness/read key is root+issuer+subject+idempotency key;
client is stored but not part of that key. Policy requests need the full principal
(including client and kind) as agreed above. Keep legacy ad hoc key semantics
separate; do not silently alias a policy request from another client. Assess the
actual 00101 schema before generating 00102. A fixed-size hash of an unambiguous
length-prefixed actor encoding can index the existing actor columns plus key;
the read must still match the full actor columns and original caller-input digest.
This avoids relying on a wide B-tree key for the maximum issuer/subject/client
strings and adds no table or principal service. Hash collision may refuse a request
but must never return another actor's row.

Old binaries use the old nondiscriminated lookup and cannot interpret policy grant
rows. The migration compatibility floor must refuse such binaries if the final 00102
layout admits multiple full-client keys that the old query would conflate. Down
must refuse when surviving rows cannot satisfy the old unique key; it must never
delete a reviewed grant or rewrite its idempotency key to force rollback. This is
a pending migration design check, not implemented SQL or a tested upgrade claim.


## Source review corrections before SQL composition

Policy revocation evaluates the returned workload projection against the grant's
expected workload, never against the returned projection's self-selected target.
This corrects one argument in the existing read/evaluator path: zero added reads,
credentials, watches or state. A wrong-target projection now refuses without
calling grant mutation.

Recorder collection scope explicitly projects collection fields. Sharing and
grantRef stay separate controls; changing recipients, sharing deadline or sharing
capture count cannot reissue collection authority or reset its accepted spend.
The activation regression observes that no second acceptance is dispatched and
original issue/expiry, authority and modeled counters remain. SQL spend preservation
is not qualified by this unit test. Activation replay returns the existing sharing
instruction, not the newly authored control; separately authorized sharing control
composition remains required before the complete workflow is enabled.

Policy requester Get/requested-list require current CollectContext on the exact
workload. Historical requester provenance is insufficient: absent/denied/wrong
or unavailable rights yield NotFound or an omitted row. Independent current
approvers keep their existing ApproveAction view. Ad hoc requester visibility is
unchanged. Service identities match the entire original principal/client; same-human
metadata across clients never changes full-client request idempotency.

This adds one current workload read per policy Get and at most one per distinct
workload in a bounded list (existing maximum 100 candidate rows), using the existing
request-local result map. The existing final identity read now reuses C03's canonical
identity comparison for visible policy metadata; changed groups/scopes/policy and
expired original bounds refuse delivery. No extra final identity read, background
cache, watcher, configuration or credential is added. Tests cover departed groups,
current denies, unavailable/wrong projections, expiry after blocking reads, service
client separation, one read for multiple grants on one workload, and unchanged
ad hoc/current-approver behavior. Policy scope/period/max/recipe and original request
journal recovery remain frozen; SQL 00102/public/node/bootstrap are still unwired.

## Migration 00102: reviewed composition and SQL plan

Base: local merge `822e79b5` composes history
`cc2ccae0b73fc7179a296f529e9aa8ae583ab547`, with approved-recording
`21806d0d2612d33bb039b6daf2971849796a999d` independently verified as an ancestor.
Packet funding remains 00100, encrypted history 00101, policy grants 00102.
Later 100 diagnostics are intentionally excluded until their canonical result.
The one code conflict preserved both current policy metadata rights and ad hoc
continuation hints; policy grants explicitly offer no personal resume/resolve.
At that merge checkpoint no SQL 00102 file or runtime/public/node wiring existed.
The source-only SQL draft below is now being implemented; runtime/public/node
wiring remains absent.

1. Extend the existing AccessGrant row with a closed discriminated policy shape.
   Preserve legacy ad hoc required preview/capture/Pod IDs, human requester,
   decision-anchored eight-hour maximum and result-access pools. Policy grants
   instead require real workload/policy identity, authenticated human/service
   requester kind, frozen accepted authority/scope/recipe/original maximum,
   original RequestedAt anchor and separate finite execution/output/observation
   spend. Forbid fake preview/capture/Pod IDs and all personal result access.
   Resolve current accepted execution by collection identity/intent version,
   not equality to every latest whole-source resourceVersion/spec revision.
   Keep original source/acceptance provenance immutable.

2. Keep the request journal in that existing grant row, separate from encrypted
   operation audit. Preserve the old partial ad hoc uniqueness/read semantics.
   Policy request keys include root, full issuer/subject/client/kind and closed
   operation plus idempotency key; use a fixed-size unambiguous actor digest for
   the index and recheck all full fields and caller-input digest. Lookup precedes
   current plan/default resolution. Original lifetime-zero/default choice,
   scope/max/recipe, periods and spent pools survive lost replies/replay.
   Hash collision can refuse, never alias another request. No new journal table.

3. Add a protected policy-period projection distinct from browser settings and
   their five-second lifecycle. The already reviewed ten-second joined observer
   accepts an original bounded protected observation. Publish it and apply any
   lower maximum to all older pending/approved policy grants in one transaction,
   using indexed set-based min(existing, RequestedAt+maxAge). Later raises never
   extend earlier deadlines. Approved historical rows remain valid records when
   a later clamp moves effective expiry before DecisionAt; new approval after
   effective expiry refuses. No revision history, paging machinery, invented
   global grant cap or unseen raw ConfigMap ABA guarantee.

4. Reserve policy grant and accepted-authority shared spend atomically under
   existing current recovery/delegation/source guards and lock order. Replays,
   restart, grant replacement and attachment cannot refill either aggregate.
   Unknown possibly-started effects remain charged. New admission resolves a
   real current Pod of the reviewed workload; no grant lifetime follows the
   historical requester's login. Current requester metadata rights stay separate.
   Add only the durable session/fence/sequence state needed for cumulative
   observation credit on the required authority renewal; do not add a quota-only
   renewal stream or fix its quantum before composed cost measurement.

5. Persist explicit attachment control receipts on the existing activate-policy
   boundary. They are semantic/idempotency state, not durable object audit:
   encrypted intent must already be acknowledged before mutation, with the
   existing outcome/replay handling. Bind exact original acceptance/grant and
   current authored grantRef; no newest-grant selection or Kubernetes writes.
   Do not let sharing/control-only changes replace accepted authority or spend.
   Separate authorized sharing control remains an explicit workflow dependency.

6. Update only necessary closed role facets, SQL queries/generated models and
   installer schema inventory. Reuse existing credentials and protected source
   producer; record any narrow added SQL execution privilege explicitly. Raise
   the binary compatibility floor to 102 because older grant readers conflate
   the new kinds/client keys. Up validates old rows before changing constraints.
   Down refuses incompatible policy/session/attachment survivors or old-key
   collisions; it never deletes/rekeys grants, refunds uncertainty or resets
   spend to force rollback. Keep the old ad hoc contract exactly testable.

Before any local external run, coordinate the owned fixture slot with root,
freeze all relevant sources, retain actual selected tests/exits, source hashes
and terminal cleanup, and cap the run at twenty minutes. No collector locally.
Planned real PostgreSQL cases (new test names will be added with implementation):
conditional row negatives and role denial; same-key full-client/operation
separation plus exact lost replies/default changes; requester/independent reviewer
versus policy executor; current-scope/refusal after lock waits; pending and
approved original-anchor lower/raise including expiry before historical decision;
concurrent grant/policy spend and revocation, restart and attachment no-refill;
Up/Down/floor and incompatible-survivor refusal. Reuse the existing
`TestContextAdmissionWithRealServices/access-grant-approval-children-pool-revocation-and-expiry`
regression (parent and subtest verified in source), plus affected purpose/installer
roles. `scripts/test-custody.py --run` is the existing bounded targeted runner;
new policy test selectors are not claimed to exist yet. Run sql-check and affected
Go/race/spec/architecture gates before qualification. No public runtime wiring or
hosted campaign until SQL review and real SQL gates pass.


Public-composition follow-up: a current sponsoring team manager who may attach or
revoke must be able to inspect the attached grant's finite state/expiry after the
original requester leaves. Existing nonrequester Get is approver-only; decide a
minimal current-manager view when composing those controls, without a grant-head
service or broader collection/disclosure authority. This does not block SQL scope.


### SQL draft smoke checkpoint

The schema-102 draft now has conditional workload-grant rows, original full-actor
request keys, accepted-settings storage and atomic lower-period clamping. It adds
immutable explicit attachment receipts and cumulative session/fence/sequence row
shapes, but their accounting/activation composition is not implemented or qualified.
The raw-predicate refusal remains. The targeted first owned PostgreSQL/S3 smoke
checks actual migration syntax, historical ad hoc Up/Down, incompatible-survivor
refusal and the request/settings component under compiled SQL roles; it is not
final schema-102 or public/executor/collector qualification.

No new credentials, Kubernetes permissions, network requests, watchers or timers
are added by these SQL adapters. The existing permission-accept credential gains
settings read/write, root-lock UPDATE(id), five grant metadata SELECT columns and
UPDATE(policy_not_after,expires_at), with the trigger limiting that update to a
monotonic overlay. It cannot inspect review/scope payloads, decide or refill spend.
The existing hub grant duty reads the accepted source/settings under its root lock.
Original observation endpoints are rounded down to PostgreSQL microseconds,
never extended. The compatibility floor is 102; a compatible Down restores 81,
while policy/session/attachment survivors refuse rollback without deletion/refund.
The simple set-based clamp retains the earlier measured complexity decision; no
revision history or new global row ceiling is introduced.


Smoke 1 (`07ad950c`) failed before Go tests during migration: PostgreSQL refused
its generated requester-key expression as non-immutable (42P17). Both owned
containers were removed; unchanged sources and cleanup were independently checked.
No test or role qualification resulted. Report SHA-256
`a8605c8a3575a1ef7a39179ae66f8d2448200f4e3edaf3f6abc6d1259f010fc3`.

The correction uses an ordinary nullable policy-only actor-key column, no legacy
backfill, extension or IMMUTABLE wrapper. The existing INSERT computes its key
from four explicit UTF-8 strings with network-order byte-length prefixes; a
conditional CHECK independently requires that same canonical key. Go computes
the lookup key with the same byte encoding and rechecks the full actor/input.
A multibyte golden is exercised in both languages; boundary/client/kind changes
remain distinct and caller-selected mismatches must refuse. Attachment keys use
an ordinary insertion-checked column too. Actual CHECK behavior remains pending
another coordinated owned SQL run; generation/unit passes alone do not prove it.


Smoke 2 (`fa5d053b`) passed the ordinary key-definition stage, then failed before
Go tests while compiling the new grant trigger (42601): PL/pgSQL parsed an
unparenthesized CASE inside an IF comparison as an incomplete condition. The
correction explicitly groups that CASE; other new IF expressions were reviewed.
No data/check/role proof resulted. Report SHA-256
`7ab5b1df971dcc4ab113791634a5d33ba5c3cd35af87c9c94c5a3f6b0c268961`,
unchanged sources, no cleanup failures, and both owned containers absent.


Smoke 3 (`1a5ee7ee`) passed the actual schema-101→102 Up/compatible Down/reapply
case (2.19 seconds). The catalog confirmed `textsend`/`convert_to` are STABLE,
`int4send`/`sha256` IMMUTABLE. The policy case failed during its existing synthetic
source setup: `policy_source_runtime`'s fixture-only column list omitted the new
`authored_grant_ref` (42501). Production compiled policy-source grants already
include it. The correction adds only that exact fixture INSERT/UPDATE column.
No request/settings data or Unicode/check proof resulted yet; group exit 1,
Go test 3.879 seconds (runner phase 59.802 including race compilation), unchanged
sources, cleanup empty, containers absent. Report SHA-256
`20f4186fb34e8f9ad310f6b53db891d03023e0f3f5a6e24db09abd8c6ee4efdd`.


Smoke 4 (`56e132a4`) passed the selected real PostgreSQL/S3 request/settings
case: `TestPermissionAuthorityPoliciesWithRealServices/policy-grants-original-request-periods-and-client-journal`
(3.32 seconds; Go 5.838 seconds; runner phase 8.926 seconds), exit 0,
unchanged 3,244 source hashes and no cleanup failures. It qualifies conditional
rows, full-client/Unicode journal lookup, original-anchor lower/raise and refusal
of unsafe rollback for that source snapshot, with synthetic protected identities
and authority inputs. It does not qualify attachment or execution accounting.
Report SHA-256
`2e3c1c40fda99e051e7a8d533347ddd6e632bda29cd769b470fd3bb554e396c6`.
The archived report and Go log are under the local build cache's
`approved-workflow/policy102-smoke-4-artifacts/` directory.

The next source batch adds an unwired attachment store on the existing
`policy-automation` SQL duty. Recovery → permission root → source → grant locks
serialize the control against source changes and review/revocation. A fresh
current sponsoring manager is checked for both new control and historical reply;
creator/requester identity is not management authority. The full actor/client/key
and original policy/grant input identify an immutable reply. Replay returns its
old receipt without restoring a cleared source pointer. Accepted authored-grantRef
changes clear that pointer, so A → B → A needs another explicit control; an
unchanged reference preserves it. No acceptance, expiry or spent counter changes.
The existing duty gains full access_grant SELECT, attachment SELECT/INSERT,
grant UPDATE(id) solely for row locking (the immutable trigger refuses ID
changes), and source UPDATE(grant_attachment_id). The full SELECT reuses the
existing locked grant decoder and all conditional immutable-field checks; a
partial reader would introduce a second verification path. The ordinary
hub-runtime role union already has full grant SELECT through its grant duty,
but the standalone policy-automation duty now reads that additional metadata. There are no new credentials, provider requests,
watches, timers or background tasks. The public activate_policy encrypted-intent
acknowledgement/outcome boundary remains unwired; this store is not independently
public execution authority. Real role-bounded attachment/ABA/replay qualification
is pending the next coordinated frozen-source run.


Attachment source gates (not SQL behavior qualification): sql-check passed with
62 generated-query files; targeted race checks passed for domain authorization
1.010s, application authorization 1.031s and PostgreSQL adapter 1.073s. The
integration package compiled and its external cases skipped without fixture opt-in
(1.072s); no real attachment behavior is inferred from that result. spec-check
passed 13,284 assertions, architecture-check 1,326 positive checks and Go
architecture 67 packages/393 imports. The first spec invocation used the system
Python without development dependencies and failed; the retained second run uses
the existing canonical spec virtual environment and passed. Actual role/ABA
cases remain pending a frozen-source PostgreSQL/S3 run.


Attachment smoke 1 (`b17c4c50`) passed the expanded selected real PostgreSQL/S3
case (subtest 3.44s; Go 5.905s; runner phase 8.676s), runner and qualification
exit 0. All 3,247 source hashes matched, sources were unchanged during the run,
cleanup failures were empty, and both exact owned containers were absent.
Report SHA-256
`640ccbc0ed808d2d823b1845f16a97da39d28f1e3b1f86289ad0204d5ce48508`;
report/log archived under
`approved-workflow/policy102-attachment-smoke-1-artifacts/` in the local build
cache. This proves the role-bounded current-manager attachment, full-client
journal/conflict, immutable reply and accepted-source A → B → A clearing cases,
with synthetic protected identity/authority inputs. It does not qualify the
public encrypted-intent boundary, node execution, or cumulative accounting.
The earlier smoke-4 evidence remains bound only to `56e132a4`.


### Occurrence-backed capture accounting batch

Observed gap: current real trigger code spends one accepted execution before
creating a policy_occurrence, but capture admission spends neither grant output
nor accepted output. Every recurring collection uses this typical path; repeated
accepted captures can therefore multiply the finite reviewed output allowance.
This is an accepted product guarantee, not a speculative extra security check.
Reuse that existing occurrence for the charge identity: add an immutable reserved
capture/grant/output tuple, rather than another journal/table or generic budget
service. Existing context_capture idempotent lookup runs before new charging.
Require an actual pending occurrence of the exact current acceptance and real
Pod; its already spent accepted execution is never incremented again. The
admission transaction atomically creates the capture, increments accepted output
and, when attached, grant execution/output, then freezes the original tuple.
All effects roll back together on refusal. Lost commit replies recover the same
capture; restart, attachment/grant replacement and source control/share edits do
not alter old tuples or refund output. Unknown started effects stay reserved.

Budget output by the existing native plan ceiling: 4,096 bytes for pod status or
the frozen recorder's bounded MaxBytes, currently at most 8 MiB. These are retained
native output ceilings, not pre-filter observation bytes. Grant/acceptance original
expiry, current source/delegation/denies/recovery and concrete Pod remain binding.
A policy requiring review needs an explicit exact current attachment; never find
the newest grant or borrow the human requester. Unreviewed context policies still
consume their accepted aggregate output. Ongoing packet/syscall observation
credit/session/fence and all-before-filter accounting are separate pending work.

Numeric cost: zero new services, tables, credentials, remote provider calls or
connections, watches, background tasks or configuration. SQL Query/Exec calls
are database round trips. Each new policy capture adds a source lock, accepted
read and occurrence lock; an attachment adds receipt and grant reads. Existing
clock queries bound those reads. Charging adds one accepted output UPDATE, one
occurrence UPDATE and at most one grant UPDATE. Final exact round-trip counts
will include database-time reads. No per-payload/chunk accounting. Existing root lock
serializes source/control/revocation; lock source then occurrence/optional grant
before storage/evidence locks. Exact counts are reviewed again against the final
code. No global grant/occurrence ceiling is added. Down refuses a reserved tuple
or nonzero accepted output, never deletes rows or refunds to force rollback.
Public activation attachment/audit and ongoing-source integration remain explicit
requirements; SQL admission does not stand in for those workflows.


Composing a changed accepted scope also clears its old attachment in the existing
ActivatePolicyAcceptance UPDATE; unchanged accepted scope retains the pointer.
A newly accepted collection scope cannot inherit an old grant's approval. This
adds the pointer column to the existing acceptor UPDATE privilege and fixture;
it adds no request. The context-admit SQL duty gains reads of the occurrence,
attachment and complete grant metadata, source UPDATE(policy_uid) solely for row
locking, occurrence UPDATE of the three reservation fields, accepted-output
UPDATE and grant execution/output UPDATE. The ordinary installed hub union
already owns those source/grant reads; standalone capture-admit now has that
additional SQL access. Existing immutable/monotonic triggers still constrain
all writes. Explicit current eligibility/recovery/expiry checks remain mandatory.


Independent review found an upgrade refill in the new counters' DEFAULT 0:
legacy trigger executions/occurrences may already have collected or possibly
started work. Up now conservatively fills both pools to the ORIGINAL authored
maxima whenever executions_spent is positive OR any occurrence exists, including
pending/refused/unlinked NULL capture replies. This is unknown conservative
spend, never a measured byte count. Pristine scopes with neither signal remain
zero and usable. Cost is one set-based UPDATE with an acceptance scan and
occurrence membership set, O(acceptances + occurrences), during the existing
migration transaction; no runtime work, parser, provider lookup or new state.
Exact backfill from retained artifacts cannot establish all uncertain effects;
adding historical reconstruction machinery has weaker value than this fence.
Previously spent legacy scopes intentionally cannot start further collection.
Restoring capacity requires explicit reauthorization/renewal under a supported
lifecycle; same-intent recurring renewal is not implemented here, and cosmetic
scope edits are not a reset mechanism. Down refuses these preserved nonzero
pools rather than discard uncertainty. The schema-101 migration test now covers
spent executions, unknown open occurrences and pristine scope with distinct SQL
fixtures; it does not claim recovered exact historical output evidence.


Mode check: ADR-249 items 2 and specs/authorization.md REQ-AUT-006 distinguish
payload-sensitive rawBytePredicate observation from the administrator's optional
recordingApprovalRequired on ordinary sanitized networkHeaders. The latter
requires review but carries no sensitive observationLimits. Reuse the existing
AcceptableRecorder/RecordingForContext gate: any raw predicate with observation
limits stays RecorderUnavailable, and unsupported raw/HTTP/syscall argument
profiles remain unsupported. No new blanket recorder refusal is introduced.
This batch reserves output for the bounded on-trigger packet capture supported
by that existing gate. It does not establish ongoing source arming/session credit;
zero observed-byte authority must not be described as permitting a continuing
source. Genuine ongoing packet/syscall policy support remains planned.

Final accounting SQL cost: the new capture-only lock helper adds five database
round trips without an attached grant (source lock, two database clocks, accepted
read and exact occurrence lock), or eight with one (receipt, grant lock and one
more clock). Charging adds two UPDATEs, or three with grant spend. Final checks
reuse existing database clock results. Each later original-policy effect check
adds three reads/clocks without a grant or five with one. No work occurs per
packet/payload/chunk. Those original grant checks prevent replacing an attachment
from transferring an old possibly started capture to new approval or spend.
The existing api-execution SQL duty gains source/occurrence/grant SELECT and
UPDATE(access_grant.id) for row locking only; no grant counter/decision writes.
The hub union already owns those reads, but standalone purpose grants are
explicitly expanded and their exact-grant test updated.


Accounting source verification before the batched real-service run: integration
package compiles; targeted domain/application authorization, capture and PostgreSQL
race checks pass (1.014s/1.254s/1.186s/1.079s respectively), sql-check passes,
spec-check passes 13,284 assertions, architecture-check 1,326 and Go architecture
67 packages/393 imports. Real SQL regression scope is the revised 101→102
historical uncertainty/pristine migration case, the existing request/settings/
attachment case and actual policy-executor capture admission with a four-capture
attached grant, replay/restart and refused fifth occurrence. These new accounting
cases are pending; no executed RED/GREEN claim is made for them yet.


Accounting smoke 1 (`da522a48`) failed overall (Go 10.063s; runner phase
40.678s; exit 1). Request/settings/attachment passed (3.25s), and the actual
schema-101→102 conservative historical/pristine migration test passed (2.93s),
including the production output-spend query refusal and unsafe Down refusal.
The policy-share/accounting case failed during new synthetic fixture setup:
WritePolicyGrantSettings returned PostgreSQL 42501 under hub-runtime, which
correctly cannot accept its own protected ceilings. Fix the fixture to use the
existing permission-accept purpose for that projection, as the earlier qualified
request/settings fixture already does; no production privilege is broadened.
No accounting admission was exercised. All 3,249 source hashes matched,
unchanged sources, cleanup empty and both exact owned containers absent.
Report SHA-256
`1daaba87f88519326eef98ac935fecba2f093c61b09738a99b29b66deaf5617c`,
archived with actual Go/provider logs under
`approved-workflow/policy102-accounting-smoke-1-artifacts/` in the local build
cache. Preserve the passing unchanged migration/attachment evidence; retry only
the concrete failed policy-share component after fixture correction and gates.


Accounting smoke 2 (`ef5a211d`) failed overall before capture admission:
settings acceptance passed under its separate duty, then the new fixture's grant
scope bytes did not hash to its synthetic accepted authority digest. PostgreSQL
correctly refused access_grant_check; the digest CHECK is unchanged. Go 2.805s,
selected child 2.35s, runner phase 22.048s, exit 1; unchanged 3,249 source hashes,
cleanup empty and both exact owned containers absent. Report SHA-256
`b51ca1afff2ab5018143b0e3866870fbc34d319bef250df8bb404fc34d5267f6`,
archived under `approved-workflow/policy102-accounting-smoke-2-artifacts/`.
The fixture correction builds one synthetic collection-scope document before
acceptance, hashes those exact bytes into authority and passes those same bytes
to the grant. It checks the domain blueprint and review hash before SQL and uses
the real typed caller-input digest. The second accepted fixture version explicitly
changes source collection intent; a sharing-only edit never reauthorizes or resets
collection budgets. These remain synthetic authority inputs to real SQL, not
production compiler/identity qualification. No product check or privilege changes.


Accounting smoke 3 (`be38a13e`) failed overall later in the fixture: it derived
synthetic Pod restart ordinals from per-acceptance execution counts. The second
accepted scope reused ordinal 1 of the same real resolved Pod; PostgreSQL
correctly refused policy_occurrence_root_id_policy_uid_pod_uid_restarts_key
(23505). Actual Tick retains the Pod's monotonic restart counter across accepted
scope changes. The fixture now keeps one monotonic ordinal across acceptances;
the product occurrence key, deduplication and all counters remain unchanged.
The first four captures, replay/restart and refused-fifth assertions were reached
before the later failure, but the selected subtest is still FAIL, not a completed
accounting qualification. Go 4.843s, child 4.39s, runner phase 23.703s, exit 1;
unchanged 3,249 hashes, no cleanup failures and both exact owned containers absent.
Report SHA-256
`31af1fc2ed21e989bfac3eba92bff03eb99b89d12861a07e88db33bacfdcf556`,
archived under `approved-workflow/policy102-accounting-smoke-3-artifacts/`.


Review of the complete sharing scenario also makes acceptance C an explicit
fourth source generation with changed collection intent. Generation 3 stays an
unaccepted control-only edit that stops sharing without changing collection
acceptance B. Both new collection acceptances now have distinct source intent;
stop/revoke/replay control transitions retain the same accepted counter pools.
These fixture corrections add no product behavior or relaxed constraints.


Accounting smoke 4 (`2319c48d`) passed the entire selected real PostgreSQL/S3
policy-share scenario: selected child 31.61s, Go 33.070s, runner phase 52.108s;
runner/qualification exit 0. The actual log records grant executions 4/output
16,384 bytes, accepted executions 5/output 16,384 bytes and no fifth reservation.
The fifth trigger occurrence remains spent but its refused capture contributes
no output/grant charge. Replays/new adapters do not add charge; later collection
scopes have distinct accepted intent and monotonic Pod restart ordinals. Existing
sharing publication after expiry/control changes, stop and revoke-all expectations
also pass. All 3,249 hashes matched; unchanged sources, cleanup empty and exact
owned PostgreSQL/S3 containers absent. Report SHA-256
`e19b5a75f8bf331ebca9e535df5a3d17cc35f101eb93065c1e10414c49f3d41e`,
archived with Go log under
`approved-workflow/policy102-accounting-smoke-4-artifacts/`.

This is role-bounded SQL/S3 component evidence with synthetic current identity,
protected authority and review inputs. It is not installed public policy-grant or
recorder qualification. The unchanged revised migration/attachment positives
remain bound to `da522a48`; failures 1–3 remain archived. Acquisition-gate testing
after attachment replacement/revocation, public activation encrypted audit,
request/review/UI wiring, finite same-intent renewal and genuine ongoing sensitive
observation/session credit are still pending. Static call-site review confirms the
new current-policy/grant gate runs on API work/start checks, never on stored
completion or publication; no later-source control blocks already gathered
artifact finalization through this gate.


### Canonical approved-workflow composition

The branch now composes canonical main `eed8594020645fe6d10f8c6565e69a6235c7507d`
(the merged/qualified approved manual workflow), history 00101 and policy 00102.
Resolve the squash-history conflicts by retaining canonical tri-state recorder
availability, the actual-parent response reserve, fixed endpoint diagnostics and
updated H2 metadata assertions, alongside history's pinned-repeat selection,
encrypted settings/browser flow and policy workload metadata eligibility.
Ad hoc original-client continuation hints remain intact; policy grants gain none.
No grant, occurrence accounting, migration 00102 or SQL query implementation
changed during this composition. Earlier real SQL reports remain bound to their
recorded sources; they are reused, not relabeled as installed composition proof.

Five critical diagnostic/wait files are byte-identical to canonical main:
owner_endpoint.go, cluster_observation_operation_client.go,
owner_endpoint_diagnostic.go, owner_route_diagnostic.go and
context_storage_wait.go. History additions preserve the independent current
request/authority cutoffs. Generated browser validators were regenerated from the
merged contracts. Initial generation failed because this worktree lacked locked
web dependencies; the existing console-install target installed the unchanged
lockfile and generation passed. No package version or dependency changed.

Actual composed gates: pre-push exit 0 (13,287 spec assertions, 62 sqlc files,
67 Go packages/393 imports and 227 console unit tests); full affected race suites
passed authorization 1.343s, capture 11.050s, PostgreSQL 2.557s, mTLS 36.860s,
presentation 74.373s and MCP 50.996s. Console build/browser-check exit 0,
Go 21.492s: actual built React/Go HTTPS with synthetic authority ran 23 browser
journeys/20 accessibility scans and four native-restart boundaries/two scans.
Those browser reports do not qualify real SQL/IdP/collectors or native transfer.
Reports/screenshots are archived in the local build cache; generated test results
were restored after archival. No extra SQL fixture, collector or hosted run was
launched, and no push/publication is implied by these local gates.


### Current-manager metadata and original-grant acquisition batch

Observed defect: after the requester leaves, the exact current sponsoring team
member may attach/revoke the team grant but Get returns not found because it
requires action-approver. The service regression reproduced this (exit 1) before
fixing it. Team continuity is a maintainer requirement; the earlier requester/
approver-only metadata rule was an agent implementation choice, now explicitly
extended for exact current pinned managers. Ordinary readers/unrelated managers,
stale denies and replaced assignment/basis identities still reveal nothing.

Reuse one GrantView and the existing get_grant/list_reviews DTO. Add a closed
adHocCapture/policy discrimination: real workload UID scope, policy UID/executor,
original authority dates and finite ceilings/spend; no fake capture/preview/Pod.
Effective grant expiry stays request-anchored. Manager visibility does not confer
independent review, evidence/history/download rights, personal continuation or a
team-wide inbox. Existing can_revoke comes from current actual control rights,
not requester provenance; Approver remains review authority. Old ad hoc shape
and behavior remain unchanged. The same browser/MCP contract and generated
validators retain parity; the existing React detail displays the finite team
scope and available control, never substitutes a new page/model or endpoint.

Numeric cost: zero new services, providers, credentials, network requests,
background tasks, configuration or durable rows. Get still reads one existing
workload projection; list still reads at most one per distinct workload in its
existing 100-row bound. Derive collection/reviewer/manager flags locally from the
same projection (at most three bounded assignment scans); final identity and
original freshness checks remain. Existing response limits stay unchanged.
The added policy metadata is identifiers, configuration and numeric counters,
not gathered user data, credentials or content authority.

Original-grant acquisition testing reuses the fourth admitted capture as an API
pod-status capture (same recipe), after its existing encrypted intent publisher.
A replacement grant cannot change that capture's immutable charged grant or
spent tuple; revoking the original stops its acquisition read while the unused
replacement remains approved. Completion/publication semantics remain separate.
The standalone api-execution SQL duty additionally needs policy_acceptance SELECT
for its already-existing contextEligibilityIn accepted-authority read. The actual
installed hub union already has that read; no grant/acceptance write is added.
New external qualification waits for root's coordinated free fixture slot.


Manager metadata verification: the old C03 Get reproduced not-found for the
current exact sponsor after requester departure (actual RED exit 1, 0.002s).
After the policy-only fix, the complete authorization suite passes, including
single-projection manager access/revoke without review, lost requester rights,
wrong workload, unavailable/stale denies, ordinary reader/unrelated basis and
replaced assignment/digest cases. Real C03 → canonical presentation tests exercise
correct workload/expiry/spend, refused review, one revocation with unchanged
spend, and no metadata after replacement of the manager assignment. Ad hoc
continuation and requester behavior remain under their existing regressions.

The same public DTO now discriminates adHocCapture/policy in browser/MCP and its
offline runtime bundle. Policy adds real namespace/workload UIDs, policy/executor,
original authority dates, finite grant ceilings/reservations and effective
request-anchored expiry; capture/preview/Pod and personal result-access fields
are forbidden. Policy continuation hints must be false. The React page displays
grant reservations with an explicit reminder that shared team/workload/admission
limits still apply; it never promises that grant remainder is usable capacity.
The existing production grant service now wires its previously unused
WorkloadPermissions port to the same existing accepted SQL permissions adapter.
No collector or public policy-execution path is enabled by this metadata wiring.

Full affected race suites passed authorization 1.359s, presentation 79.936s,
PostgreSQL 3.019s and bootstrap 54.591s. Final pre-push exit 0 includes 229 console
unit tests, canonical generation, SQL generation, specification/architecture and
vet. The first TypeScript check correctly found the newly optional preview ID in
manual continuation code; the handler now explicitly requires the existing ad
hoc mode/preview before using that path. No policy can enter personal continuation.

Actual console build/browser-check passed, Go 21.887s: 24 journeys/21 accessibility
scans plus four native-restart boundaries/two scans. Its new policy-manager
journey uses real built React → HTTPS/cookie/CSRF → canonical Go presentation →
real C03 with synthetic identity/store/projections. It shows original
workload/executor/expiry and 4 of 10 executions/32 of 64 MiB reservations, offers
no review/step-up/personal continuation, and revokes exactly once without changing
spend. No external browser requests or accessibility/CSP/runtime violations.
Browser reports/screenshots were archived before restoring tracked test outputs.
These facts are not SQL, IdP, encrypted-audit, native collector or deployment proof.

The expanded real SQL original-grant replacement/revocation acquisition case is
compiled but not run yet; retain that gap until the coordinated fixture completes.
Shared accepted-policy counters in the existing policy-status route remain a
required next public-composition step, not an optional alternative to grant status.


### Composed installation inventory (history 3673 + policy 102)

Retain history's qualified eviction mutation-count fence and exact two-table
installation correction by merging 3673c264. The complete permanent inventory
is 130 names (history 127 plus policy_grant_settings, policy_grant_attachment,
policy_observation_session); the previous literal 128 rejected this supported
first-install path. The old ordering test reproduced that rejection (exit 1,
0.010s); no installed policy success is inferred from history's schema-101 pass.

Replace only the two table-catalog bounds with the closed compiled inventory:
complete/activation reads admit exactly 130 and fetch at most 131 rows to detect
unknowns; partial replay permits the two exact legacy transient tables, at most
132 known names and one overflow row. Unknown names still reject immediately,
and complete equality, owner, permanence, RLS, pristine-table, original-prefix,
original deadlines and binary floor 102 remain unchanged. The unrelated 128
migration-file/version and filename bounds remain unchanged. Added real-SQL
regressions create unknown names before/after the complete ordered inventory,
require refusal, remove them and require successful exact replay; not yet run.

Cost: zero extra catalog queries/round trips, credentials, services, watches,
background tasks or configuration. Existing catalog reads gain parameterized
LIMITs, replacing one unbounded read and one literal bound. Each existing
pristine scan gains three SELECT EXISTS round trips compared with history 101
(five compared with canonical 100); no per-workload scaling. Initial preparation
and activation each gain SELECT and MAINTAIN on those exact three policy tables:
12 role/privilege tuples total, and six deduplicated grant-option tuples for the
existing setup-manager union. History's two tables account separately for eight
role tuples/four manager tuples. No runtime role or write privilege is added by
this inventory composition. A larger arbitrary constant or omitting tables
would leave the observed exact-inventory failure unresolved.


Composed local verification: initial inventory/role gates pass PostgreSQL 0.078s
and integration compilation 0.015s; full PostgreSQL race suite passes 2.557s.
`make pre-push` actual exit 0 includes all 229 console unit tests, canonical
schema/SQL generation, specification, architecture and vet gates. Logs are
archived as policy102-history-composed-{prepush,postgres-race}.log under the
existing approved-workflow cache. No external service qualification ran during
this composition; both new real-SQL scenarios remain pending.


Composed smoke1 on frozen a3f9c8da: overall runner/Go exit 1 (Go 21.712s,
phase 52.037s); initial-schema parent passes 16.96s. All 13 direct schema
children pass, including unknown-first/last catalog overflow and both nested
activation changed-database/changed-postmaster cases. This is genuine schema-102
first-install/role/prefix/incarnation qualification with synthetic protected root,
not a deployed installer proof. All 3,258 source hashes match, source unchanged,
cleanup empty and exact owned n4fzsg3r PostgreSQL/S3 containers absent. Report
SHA-256 78ee813a274f6fdaeb90e0837733069278423dd509643de129e30019e189a9a7;
report/log/provider evidence archived before removing untracked result copies.

Policy-share reaches the expected 4/16,384 grant and 5/16,384 accepted accounting
checkpoint, then its new acquisition fixture fails before adapter construction:
it incorrectly requests retired installed-purpose api-execution from the public
role renderer. That name remains a shared hub duty; the renderer correctly
refuses it. Correct the fixture to existing compiled hub-runtime union, as other
policy fixtures already do. No production privilege, constraint or role-purpose
change; standalone-duty exact grant tests remain separate source checks. No
acquisition success is claimed and no automatic rerun is authorized.


### Shared accepted-policy budget status composition

Observed gap: get_grant correctly shows only its own reservations, while the
existing get_policy_status exposes accepted executions but omits the shared
accepted native-output/observation pools. Add four required typed fields to the
same browser/MCP status data: collected_bytes_spent, max_collected_bytes,
observed_bytes_spent, max_observed_bytes. The existing SQL acceptance row already
contains both counters, and decodePolicy already provides original authored
ceilings; use these exact values, including conservative legacy saturation.
No subtraction from grants or inferred measured bytes. Preserve the existing
current viewer identity/whole-workload metadata checks, recovery/source state,
original expiry and final freshness; status grants no collection or evidence
access. Browser labels native output as reserved and observation as charged,
explains shared policy scope, and retains the existing explicit Refresh action.

Complexity/cost: zero new SQL queries/round trips, API calls/connections, roles,
privileges, background tasks, timers, watches, dependencies or configuration.
Four bounded integers add under 160 JSON bytes per existing status response.
Existing projection/audit and privacy contracts remain, no new failure state or
public endpoint. A per-grant substitute would hide the actual shared ceiling;
a separate budget service would add cost without improving this workflow.


Review found one adjacent protected-result gap: GrantService.Revoke returned an
already-revoked replay directly before final identity validation. A blocked-store
regression reproduces metadata disclosure after same-principal group loss,
identity expiry and original manager-eligibility expiry (all three RED, exit 1,
0.008s). Fresh/replay now converge on existing finalGrantMetadata and preserve
the original policy management deadline. Fresh retains one final identity read;
replay acquires its missing final identity check. No second workload or grant
read, new freshness interval or mechanism; refused replies do not undo/refund a
previously committed revocation or its counters. Ad hoc uses its existing final
check. Current manager/get and manual regressions remain binding.


Shared status/replay verification: full race suites pass capture 11.116s,
authorization 1.355s, presentation 80.516s and PostgreSQL 2.573s. Tests include
current team-maintainer status after creator departure, refused lost membership
and final identity expiry, canonical distinct accepted counters/ceilings even
after expiry, and all three blocked-replay regressions. Existing canonical status
fixtures with finite zero output/observation budgets validate unchanged.

Actual console-browser check passes (Go 22.598s): 25 journeys/22 accessibility
scans plus four restart boundaries/two scans. The new journey uses built React
through HTTPS/cookie/CSRF/canonical operations into the real policy-status service
with synthetic accepted ledger/source/projection/recovery. It shows accepted
5/100 executions, 16,384/1 GiB native-output reservations and 0/0 pre-filter
observation charges, with explicit refresh; no new polling, external requests,
CSP or runtime errors. Archive:
/home/phil/.cache/asservat-build/approved-workflow/policy102-status-browser-artifacts.
This is not SQL, IdP, audit, collector or installed qualification. First pre-push
caught required-field array ordering drift between browser/MCP; canonical order
was aligned and regeneration/final pre-push exit 0 passes all 230 console unit
tests plus full schema/SQL/specification/architecture/vet checks. Earlier failure
logs remain archived. The corrected original-grant SQL case and actual SQL
accepted-pool status assertion still require the next coordinated focused run.


Focused status/acquisition smoke1 on 87e3f492: runner/Go exit 1, child 5.86s,
Go 6.317s, phase 9.176s; all 3,260 source hashes match, unchanged, cleanup empty,
exact owned ihvcclkp PostgreSQL/S3 absent. Absolute archive:
/home/phil/.cache/asservat-build/approved-workflow/policy102-status-acquisition-smoke-1-artifacts;
report SHA-256 7c401adc163c12eae357e6137966e09a91215aa506d675e4afc1fa3e7c79abce.
The real shared-status assertion and original prepaid API acquisition read pass
before the replacement callback, where the fixture attempts an existing role.
The shared narrowRole helper takes the first 12 UUID characters, constant for
custodyID's monotonic test IDs; invoking the grant helper twice with its same
prefix collided. Scope the helper's two fixture login prefixes by their already
distinct fixed original/replacement request keys. No global helper, production
role or privilege change, and no replacement/revocation success claimed. This
failure is retained; the host slot was released to storage qualification and no
automatic repeat is authorized.


### Public request/review/attachment composition (2026-10-28)

Use request_policy_grant as one typed browser/MCP command over the existing C03
RequestPolicy service; callers select only an exact named policy/UID pin and
finite limits/period, never authority, scope bytes, requester or a Pod/capture.
Reuse existing GrantOperations/get_grant detail and independent decide_review
with real step-up. Keep original actor/client journals and original request
expiry. Use the current get_grant projection for the command result rather than
introducing another policy view model: this adds one existing grant read and one
existing workload metadata projection on a rare approval request; exact SQL
round trips are recorded with the implementation, not called network-free.

Add optional grant_id to existing activate_policy input. The real activation
service resolves the policy and current actor, preserves acceptance/audit, and
calls existing AttachPolicyGrant only when accepted-policy audit is acknowledged.
The outer AuditedOperations already acknowledges encrypted intent before inner
service work and records its outcome. Include all new input fields in existing
normalization/MAC and exact immutable request key; unknown Begin never mutates,
unknown outcome never refunds or fabricates a new attachment. No new audit
worker/table/service or public resume hints. SQL102 extends existing closed
operation_audit_lane/input functions for request_policy_grant; Down restores
previous names and refuses incompatible retained policy state as before.

Production producers already exist: PolicyGrantPlans recompiles the pinned
accepted source with the same recorder/profile/filter compiler and verifies its
exact scope digest; AccessGrants reads current accepted settings and original
request journals. Wire these and WorkloadPermissions, not fixture authority.
Reuse the existing manual filter compiler through typed DTO conversion; no new
compiler dependency or profile approximation. Join the existing settings observer
under the permission-worker's existing lease, using its protected cached identity
reader and permission-accept credential. Incremental bound: at most one source
read/10s (at most three Kubernetes HTTP requests per refresh =0.3 API/s), one SQL
projection transaction/10s, fewer on exact cached observations; no new watcher,
credential, worker workload or table. Source validity is the original 30s; cache
reuse cannot renew it. The existing observer child is joined on lease loss.

Recorder activation/execution currently lacks production composition: the trigger
still only compiles/submits pod-status and must never substitute that for packet
recording. Keep sensitive acquisition without concrete observation/session bounds
unavailable, preserve supported ordinary qualified headers, and compose genuine
recorder submission next. Public metadata/review/attachment alone does not finish
ongoing source arming, all-before-filter credit, native evidence or installed
policy workflow qualification.


Public composition cost refinements: settings are one transaction per fresh
observation, not one SQL query. The normal transaction executes five work SQL
calls (lock, clock, read, write, final clock), plus existing setup Exec and
BEGIN/COMMIT = eight database round trips before driver first-use preparation;
initial/lower maxima add one clamp call = nine. Thus steady accepted observations
at 10s cost about 0.8 DB round trips/s (0.9 on a clamp), in addition to at most
0.3 Kubernetes requests/s; exact unchanged cache hits skip SQL. Existing bounded
transaction retry stays under its original five-second total. One serial joined
observer child/timer runs inside the existing permission-worker workload/lease,
with no new worker deployment, watch, credential or table.

For usable controls status also reports accepted collection_kind (from the
already-read authority actions) and optional attached_grant_id. The latter is
folded into the existing purpose-specific status source read through a bounded
LEFT JOIN to the exact current receipt/root/policy/acceptance/authored reference;
authority digest is checked after accepted-record decode. No additional round
trip, mutable denormalized grantID or lookup by historical control key. Generic
source authority readers remain unchanged. The status role already has receipt
SELECT. Missing/mismatched current pointer fails unavailable; attachment ID never
claims current approval eligibility or recorder readiness. This addresses stale
receipt replay without an extra O(attached policies) query in multi-policy views.


Public request final-authority regression: while composing the command, fresh
RequestPolicy and immutable replay reproduced protected-result disclosure after
same-principal group loss during blocking storage/projection (both RED, actual
exit 1, 0.011s). Both now use existing finalGrantMetadata at the same final read,
with no additional workload/SQL read. The stored original request remains once,
with zero execution spend; refusing the reply cannot erase uncertain history.
This extends the same demonstrated final policy-identity contract as get/revoke,
not a new freshness mechanism.


The source has a 30-second observation interval with a healthy 15-second trigger
poll, so there is no inherent normal-operation freshness gap. After a genuinely
expired source observation (for example a >30s observation outage), the initial
SQL-first plan could fail before reading the restored protected object. The
single canonical request
now binds policy_name plus UID, and its plan reads that protected exact object
once, persists its original observation through existing SourceWriter, then reads
current accepted authority and recompiles those same bytes. No extra Kubernetes
read versus the intended plan, TTL relaxation, watch or SQL locator lookup; one
existing source-observation transaction per fresh request. Immutable request
lookup still happens before all new source/settings interpretation on replay.

There are no deployed production schema-102 policy-grant requests: this branch
has never been published and all recorded requests were disposable owned fixture
data, with exact source snapshots retained. Update this one unpublished canonical
v1 input/digest and fixtures together; do not retain compatibility versions or
fallback ports solely for prototypes. No real receipt is rewritten. The name/UID
pin is validated again against the accepted record and actual protected source.


The source-first ordering regression models an original valid source observation
expired after 31s, then a new actual named protected read. It retains that read's
original 30s deadline and the separately bounded five-second recovery/preflight
result, plus unchanged authority/expiry/pools. Failed observation has no fallback
to SQL authority. Its mutation of current negative/source watermarks occurs only
inside the existing acknowledged outer public operation intent. It is never
acceptance, renewal or permission to collect. The earlier five-versus-15 claim
was a diagnostic error, corrected before qualification or publication.


Review effect-bound cost/qualification: four blocked fresh/replay reviewer cases
(group loss and original eligibility expiry) reproduced RED (exit 1, 0.012s).
The same Store context now retains earliest original identity/reviewer and fresh
approval step-up deadlines, truncated down to microseconds. Its existing UPDATE
also compares database time with the inherited bound (one scalar parameter, zero
new queries/permissions/tables). Replay does not demand a new step-up. This is
original-bound enforcement, not immediate role-change revocation. The compiled
public SQL fixture holds the actual row beyond both narrowed reviewer and step-up
bounds and independently reads decision NULL after release. No actual SQL RED or
GREEN has run yet; do not replace that evidence with a hidden-error assertion.

Public request post-read detail cost: seven work SQL calls in the existing grant
read/workload projection, two transaction setups and BEGIN/COMMIT pairs = about
13 steady round trips before first-use preparation, plus two existing current
identity resolutions. It reuses one existing DTO and actual CanRevoke rather than
duplicating rights or a view model. Source observation costs six work calls plus
setup/BEGIN/COMMIT = nine steady round trips per fresh named request; no additional
protected Kubernetes read. These are per human/service approval request, not
per packet, policy poll or ongoing authority renewal.

Public fixture preflight now uses actual PolicyGrantPlans, typed composition
conversion and the same profile compiler, rather than a synthetic plan/scope.
Its pinned genuine libpcap corpus accepts exactly `tcp dst port 80` and refuses
other expressions; this is not a host libpcap qualification. The accepted scope
hashes the compiled configuration, original delegation/owners and original
64 MiB output ceiling. The public request selects 32 MiB for two executions;
held-row probes select 16 MiB, matching the builtin action ceiling. Protected
Kubernetes source, verified IdP/step-up and initial trust remain synthetic facts.
Source refresh is dispatched only inside the outer acknowledged intent; both
unknown-intent cases independently compare actual source observed_at, in addition
to checking no grant/attachment mutation. A separate external source-observer
simulation performs authored-ref A→B→A. This does not execute a recorder.

Local public composition checks: final canonical source-order races and
pre-push passed (actual exits 0); the final fixture compiler/compilation check
passed in 0.014s. Built React → actual Go HTTPS browser run 5 passed (actual exit
0, Go 23.199s): 25 journeys, 24 accessibility scans, no external requests or CSP/
runtime errors, plus the native-restart checks. Browser reports/screenshots were
archived before restoring tracked results at
`/home/phil/.cache/asservat-build/approved-workflow/policy102-public-browser-5-artifacts/`.
This uses synthetic server authority/store and does not qualify SQL audit,
protected Kubernetes producers, installed execution or sensitive observation.
The new actual SQL public/audit/held-row checks are still pending coordination.
Final affected race run also passed, actual exit 0: authorization 1.356s,
capture 11.074s, PostgreSQL 2.596s, bootstrap 54.629s, presentation 87.126s,
audit 1.031s and browser transport 17.805s. Final pre-push exit 0 includes
spec/architecture/design/schema/OpenAPI/SQL generation, console 231 tests and
Go vet/format checks. No external fixture or collector ran for these checks.

Combined public SQL/S3 batch 1 at clean 134080ef terminated exit 1 (Go 47.590s,
harness test phase 68.467s). Actual positive children: policy-share accounting
36.83s, including original-grant acquisition before/after attachment replacement,
original revocation refusal, unchanged tuple/pools and shared status; original
request/attachment 3.13s. Migration's full top-level body passed 2.72s, including
new audit-name Up/Down mapping and legacy conservative spend; the report's
passedTestNames lists children only. The new public audit child failed 3.00s in
fixture configuration replay: refresh recomputed audit-pool ValidUntil while
ExpectedRevision remained zero. The existing immutable configuration replay
correctly refused this. Provision both finite pools once at their original
anchor; do not refresh their deadline, revision or spent counters. No product
permission/constraint change. The public unknown outcome/source and held-row
SQL assertions did not complete and remain pending.

All 3,264 hashes independently matched the frozen snapshot, sourceUnchanged=true,
cleanupFailures=[], exact `asservat-custody-ggze1ry6-postgres`, `-s3` and their
network absent after terminal. Archive before source changes:
`/home/phil/.cache/asservat-build/approved-workflow/policy102-public-composed-smoke-1-artifacts/`;
report SHA-256 5aff42437209b9273ac028c085086727a92aa6df49474b06a524ad53ce4cffb4.
Reuse these unchanged positive cases; a next run requires reviewed focused
public-fixture selection, not an automatic repeat of the combined batch.

Focused public run 2 at clean 168aec43 terminated exit 1 (Go 5.170s, harness
phase 25.803s). Original unknown-intent/source-no-mutation and unknown-outcome/
one-stored-request assertions were reached; same-key result recovery failed.
No PostgreSQL product permission/constraint error accompanied it. The actual
PolicyGrantPlans producer emits `policyCollection`, while the public grant reason
enum accepted only rawBytePredicate/recordingApprovalRequired. Earlier synthetic
wire/browser fixtures used those old reasons and masked the contract mismatch.
Using the actual producer reason reproduced local canonical-route RED (exit 1,
0.435s); the closed browser/MCP enum now includes policyCollection for request,
detail and list metadata. Sensitive action reason enums remain unchanged. Product
copy describes separate finite recurring approval/budgets without claiming raw
sensitivity or installation-required approval. The same route is GREEN (race,
exit 0, 3.287s). Existing closed FixedStep diagnostics are now logged by the SQL
fixture on failures; no new diagnostic mechanism or production permission.

All 3,264 source hashes independently matched, sourceUnchanged=true, cleanup[],
exact `asservat-custody-egt4vrqk-postgres`, `-s3` and their network absent. Archived
before source edits at
`/home/phil/.cache/asservat-build/approved-workflow/policy102-public-focused-2-artifacts/`;
report SHA-256 b82d9259a3db3e1b9acdbf2349ec940e3e2944c97d278c259577410d8cac16c9.
No automatic retry. Complete public attachment/audit recovery and actual held-row
NULL decision assertions remain unqualified until reviewed focused SQL GREEN.
The reason-contract correction passed final pre-push (actual exit 0, including
231 console tests) and actual built-browser run 6 (exit 0, Go 23.097s,
25 journeys/24 accessibility scans plus native-restart). Manager and newly
requested policy detail now exercise policyCollection end-to-end and assert its
finite-budget explanation. Reports/screenshots archived before tracked restore:
`/home/phil/.cache/asservat-build/approved-workflow/policy102-public-browser-6-artifacts/`.
These browser facts still use synthetic accepted authority/store; SQL public
completion/held-row proof is pending a reviewed focused run.

Focused public run 3 at frozen 8caf2ee4 passed, actual terminal exit 0 (Go9.703s,
public child7.32s, held reviewer1.75s/step-up1.77s; harness49.592s). Both request
and attachment reached audit-begin/object and audit-finish/object uncertainty,
then recovered exact journals. Source-before-Begin assertions passed. One grant,
one immutable attachment, original expiry, zero execution/output spend; six
independently encrypted acknowledged operations and two uncertain outcomes.
Both actual held-row cases independently read decision NULL after releasing the
lock beyond the original bound. This is unit RED / actual SQL GREEN; no actual
SQL RED source variant was run. All3,264 hashes match, sourceUnchanged=true,
cleanup[], exact5z8fx0u4 PG/S3/network absent. Archive:
`/home/phil/.cache/asservat-build/approved-workflow/policy102-public-focused-3-artifacts/`;
report SHA-256334c26892d87e786d3c90ed7766e6148f72e05b45d756474eaddb0e21d5e21df.
Protected source/IdP/initial trust remain synthetic component facts. Reuse the
combined134080 migration/attachment/accounting positives; this does not qualify
installed recorder execution or ongoing observation.

Next producer slice (approved existing S-04 plan): accepted packet policies
currently hit three concrete incompatible branches: trigger compiles only
pod-status and calls its Preview; generic policy capture eligibility requires
kubernetesSnapshot; recording settings look up the internal policy issuer and
approval asks a policy principal to open a human ad hoc review. Reuse the same
recorder compiler and PreviewComposition for the actual triggering Pod, original
occurrence key, ContextSubmission and encrypted capture intent/start. Permit only
the compiled supported packet mode; sensitive raw predicates keep existing
RecorderUnavailable until real observation authority is composed. Atomic
admission checks the actual recorder/snapshot action against accepted actions
before spend, retaining the original grant/recipe/counter/deadline checks.

Complexity/cost: this fixes all otherwise-unusable accepted packet policies,
not a new speculative recovery mode. Zero new watch, worker, listener, credential,
network exposure, table or SQL query/round trip is intended. Pure bounded action
checks occur in existing eligibility/admission. Existing recording settings read
uses accepted settings issuer provenance from the private request-owned policy
identity/cache; it does not reauthenticate the creator or consult personal
membership/account state. No extra acceptance read or second settings fallback.
Same one profile/filter compilation per packet-policy poll plus the existing
actual preview compiler; measure the combined path before claiming CPU cost.
Same 30s source /15s poll and existing finite attempt/deadlines. New absent-private
settings provenance refuses packet preview, with no fallback or new config knob.
No instant role-change revocation or separate machinery is introduced. A smaller
metadata-only change cannot produce an actual recording; installed/native and
ongoing qualification remain required after this source slice.


Producer local defects reproduced before fixes: a valid packet policy failed
existing shared eligibility with OutsideDelegation (unit RED exit1,0.001s), and
its real recorder preview could not use protected settings under the internal
policy issuer (unit RED exit1,0.005s). Current tests preserve the actual team
reader audience and deny sponsoring-team loss; use only accepted settings
provenance, refuse ordinary policy-shaped CurrentIdentity without the private
view, and refuse absent/outage/changed issuer or requirement after preview.
The private view reads only the existing cached accepted snapshot (asserted no
additional acceptance read), never creator credentials/groups. Trigger tests
reach the existing real recorder preview/request with the original occurrence
key/Pod/executor/recipe, refuse a changed compiled scope before Tick, and retain
the raw observation refusal before occurrence spend or personal review.

Actual bounded pure poll compilation with the statically linked libpcap1.11.0
prefix, GOMAXPROCS2 on Ryzen7 5700X3D (three1s samples per case, actual exit0,
Go7.023s): ordinary `tcp dst port 80` full policy/profile/DTO/filter/canonical
compilation117.158–117.512us/op,59,995–60,005B/op,267allocs/op; inert raw filter
119.391–120.877us/op,60,206–60,211B/op,270allocs/op. No capture/device/socket,
protected source/SQL read or recurring worker ran. At200 policies/15s, arithmetic
for this ordinary input is about1.57ms CPU/s (0.157% of one core),0.80MB allocated/s;
at1,000 policies,7.83ms/s (0.783%),4.00MB/s. These are scaled pure local costs,
not measured end-to-end CPU, GC retention, concurrent compilation or maximum
filter complexity. The existing compiler mutex remains; no cache/configuration
was added without demonstrated need. Complete runtime/workflow costs and native
qualification remain pending.
The exact linked compiler version was independently printed by a bounded
single-iteration diagnostic: libpcap1.11.0 (64-bit time_t, TPACKET_V3), actual
exit0/Go0.020s; its cold first ordinary compile was498.572us,165,344B/1,670allocs.
Do not substitute that one-shot sample for the repeated steady measurements.

Producer affected races passed (actual exit0): domain authorization1.478s,
application authorization cached, capture11.262s, PostgreSQL2.579s,
bootstrap54.013s. Pre-push exit0 includes231console tests and repository contract/
architecture/SQL generation/vet/format gates. The new focused SQL fixture compiles
but has not run: actual Tick baseline→higher restart spends one accepted execution;
packet admission/replay must charge8MiB native output and one grant execution
once, while snapshot-only authority/attachment must refuse the actual recorder
with zero output/grant reservation. Each case has one full8MiB storage slot;
negative denial cannot be attributed to a four-kilobyte or exhausted fixture.
Exact generated grant request/scope/digest, finite settings original anchor,
role names, source/permission freshness and independent cleanup are reviewed
before any coordinated external run. This is not a collector/start/publication
or native-recorder execution qualification.

## Local callback meter component (2026-10-28)

This isolated component starts from `867ed8d7`. It does not issue authority,
change public wires, migrate SQL, or enable the raw recorder. Finite onTrigger
with exactly one packet action per real capture is the first composition target;
default ongoing source arming remains separate required work.

Binding requirements before later enablement: (1) retain UNIQUE capture and one
packet action, so actions cannot each receive the aggregate credit; (2) existing
capture/expectation joins prove Pod/action/program but the regional API execution
row does not prove actual node identity; (3) persist actual node UID, boot ID,
collector Pod UID/epoch and accounting-rule digest from authenticated node
resolution, with an under-channel-lock exact tuple comparison at enqueue; (4)
issue only after SQL commit/current checks, renew the original tuple/fence/grant
with monotonic sequence, never a replacement process; (5) terminal rows need
existing custody/backing cleanup after original cutoffs and settled references,
without refund or credit recreation. This local meter implements none of those
issuer/channel/persistence responsibilities.

The gate checks the original engine wire length before Recorder.Add (therefore
before maintained BPF matching), including discarded/malformed/output-full input.
It distinguishes observed input from the existing retained WireBytes. Missing or
invalid length stops without a fabricated debit; engine loss is unknown input,
never zero input or refundable credit. One local mutex serializes debits and
permit updates. The engine receives the meter cancellation context; returning a
callback error alone is insufficient. Lease/session timers also stop an idle
engine, and its synchronous return joins acquisition before capture resources
are released. No buffered packet copy or per-packet network/SQL call is added.

Accounting rule `wire-token-bucket-v1` uses existing integer ObservationMeter at R bytes/s,
with initial/max burst R bytes (one second), an average/token-bucket rate rather than
a strict rolling-one-second cap. Both cumulative prepaid credit and
rate must admit a whole original frame. A frame larger than R is refused;
credit does not wait/refill. The finite rate upper bound includes the burst:
ceil(R * remaining duration) + R, intersected with reviewed cap/remaining pools.
This is a conservative reservation bound, not measured input. Exact duplicate
permit updates do not recreate rate tokens or credit. General ongoing prepayment
quantum and trusted renewer remain undecided by this component.

Complexity gate (estimates before code):
1. Missing pre-predicate debit is established in Recorder.Add, so enabling raw
   predicates now would fail the accepted all-input accounting contract; frequency
   under enabled sensitive capture is every delivered frame (currently refused).
2. No: maintainer has not accepted unbounded sensitive observation.
3. Required finite sensitive recorder path; existing sanitized path unchanged.
4. Published Gadget supplies packet_size; established local token bucket reuses
   the existing byte-nanosecond ObservationMeter. No custom gadget, BPF or packet parser.
5. Zero privileges, credentials, endpoints or dependencies added.
6. Two states, running/terminal, with closed terminal reasons; no fallback.
7. Zero new knobs. Fixed burst is part of the accounting version.
8. Existing pinned Gadget callback/source length and BPF evaluator only.
9. O(1) state/session, one callback-owner mutex plus one gate mutex per callback, one lease
   timer/session and one engine-cancellation callback; zero per-packet SQL/API/network,
   zero periodic renewer/watch. CPU/allocations must be benchmarked, not guessed.
10. No wire/schema change; deleting this unused component restores base behavior.
11. Keeping raw refusal is sufficient today; this component is the smallest
    testable next step toward accepted finite enforcement, not rollout proof.

Local component evidence (synthetic inputs, no Gadget execution): removing the
pre-Add Consume call makes zero-match regression fail in 1.00s with actual exit 1
because the engine is never canceled; restored gate passes. The tests exercise
real packetInput -> Recorder.Add -> maintained BPF/decoder/output limit, with
fake engine delivery and no authority/store. Credit/rate/length refusal, cancelled
parent, idle original/renewed lease, original session expiry, conflicting/lower
sequence, cumulative-credit preservation, changed boot/action/scope/epoch and
unknown engine loss are covered. Synchronous engine return is asserted after
cancellation, including a queued post-cancel callback; no collector was run.

Final affected `go test -race` passed: collector 1.006s, packets 1.027s,
bootstrap 54.302s. Canonical `make pre-push` exited 0 (230 console tests,
13288 specification assertions, 1326 architecture checks); Go architecture
passed with 67 packages/393 internal edges. The existing pure domain meter and
its tests are unchanged. The lifecycle wrapper belongs to node bootstrap;
no domain context dependency or architecture exemption was added.

AMD Ryzen 7 5700X3D, GOMAXPROCS=2, three runs of 100000 callbacks each:
median baseline -> metered zero-match 13.63 -> 74.84 ns/frame; malformed
32.93 -> 96.48 ns/frame; output-full 64.69 -> 129.10 ns/frame. Incremental
cost is 61.21–64.41 ns/frame. Zero-match/output-full stay 0 B/op, 0 allocs/op;
malformed remains the decoder's 16 B/op, 1 alloc/op on both paths. These are
shared-host synthetic microbenchmarks using fixed 64-byte wire lengths, not
native Gadget throughput or end-to-end overhead percentages. Per-source setup
allocation/CPU and combined installed cost remain unmeasured. The new gate and
callback helper total 278 implementation lines, with 512 test/benchmark lines
before this evidence note; no packet bytes are copied by the gate.

The local timer/control cost is exactly one lease timer, one derived cancellation
context and one engine-cancellation AfterFunc per metered source, plus the runner's
joined engine call; there is no periodic goroutine or renewal loop. Existing
ObservationLease's <=60s current-lease limit and <=1h original-session limit remain.
REQ-AUT-006 and action-lifecycle require rate ceilings but do not define a strict
rolling-second algorithm; this component pins the existing one-second-burst
integer implementation explicitly. Eventual review/SQL permit must bind that
accounting identity before enabling sensitive predicates. Prefix access soundness,
authenticated actual-node resolution/enqueue binding, issuer/session SQL, terminal
row cleanup and default ongoing source arming are still required. Upstream events
that never reach the node frame callback are not measured here; loss remains
unknown and reserved spend is never refunded.

Duplicate permit comparison uses timestamp instant equality, so private-wire UTC
normalization/loss of Go monotonic metadata cannot turn an exact replay into a
conflict. The replay regression also proves that rate tokens remain spent.

Independent review correction: an already-dispatched old AfterFunc can wait for
Update's mutex, survive Reset, then wrongly stop the renewed source. The expiry
callback now compares the current lease while holding that same mutex. A regression
joins the obsolete callback while renewal wins the mutex; restoring unconditional
Stop reproduces failure (0.20s, actual exit 1). All observation race tests pass on
the correction (5.202s, actual exit 0). The full-suite/pre-push/benchmark numbers
above describe checkpoint `632746cf`; the packet debit/recorder benchmark path is
unchanged by this timer-only fix. No additional timer, worker, service or authority.

The clean producer checkpoint is 3dd5f544. Only the independently reviewed local
meter commits were then composed: 632746cf as 480b22af and ba585360 as f120b6ea.
The plan's append conflict retained both public/producer and meter sections.
No stale branch merge, SQL/node authority issuer or raw-path enablement occurred.
At composed f120b6ea, one affected race run passed (actual exit 0): bootstrap
54.634s, packets 1.028s; unchanged collector/capture/authorization/PostgreSQL
packages reused Go's test cache. One composed pre-push also exited 0, including
231 console tests and the repository contract/architecture/SQL generation/vet/
format gates. Logs are `policy102-producer-meter-composed-{race,prepush}.log`
under the existing approved-workflow archive root. No external fixture ran for
this composition. The next reviewed SQL selection is only the new recorder
team/action case plus existing policy-share/accounting original-grant positives;
reuse public focused-3 and unchanged inventory/migration evidence. Complete
SQL/node binding/channel/pre-filter/native and ongoing qualification remain open.

Composed SQL batch at frozen f94be53c terminated exit 1 (Go 44.905 s, harness
67.628 s). Existing policy-share/accounting passed 36.81 s, including the original
grant acquisition/replacement/revocation/status assertions with unchanged pools.
Both new recorder cases reached actual Tick but stopped before admission at
retention resolution (4.03 s / 3.60 s). The baseline covers packet evidence;
the fixture captured its validation time before the existing blocking retention
helper observed a newer protected snapshot. Freshness correctly refused that
older time. Validate retention after the read returns, retaining the original
identity, capability/target/storage, grant/policy and plan deadline. No production
guard, policy, permission or interval changes. The other captured times were
reviewed: permission/source observations precede their consumers; original
acceptance/submission anchors remain fixed; admission obtains fresh recovery
after retention/compilation and the current accepted read; none renew an original
execution bound. The focused fixture compiles locally after this correction.

All 3,271 hashes independently matched, sourceUnchanged=true, cleanup [], exact
`asservat-custody-v4hl9ge_-postgres`, `-s3` and their network absent. Archive before
source edits:
`/home/phil/.cache/asservat-build/approved-workflow/policy102-producer-meter-smoke-1-artifacts/`;
report SHA-256 8bc01759ee8ea9284d3f1861bc22e78c527262c503480b820d847258004144d9.
Reuse the existing positive; next qualification requires reviewed focused new
recorder child only. Real recorder admission/replay/action-pool assertions remain
pending; Tick and local source passes are not their substitute.

Recorder focused run 2 at frozen 37dfe108 terminated exit 1 (Go 7.957 s,
harness 27.405 s). Retention resolution passed; both recorder cases stopped at
the adapter's pre-transaction structural guard. The fixture called unreviewed
AdmitContext with an approvedAcceptance-marked RequireApproval plan; that guard
requires a preview ID. Production ContextSubmission already uses the reviewed
entrypoint. Correct the fixture by persisting its exact compiled passive preview
and calling AdmitReviewedContext with ContextRequestDigest of that preview for
both initial admission and exact replay. Do not set RequireApproval false or
weaken/export the production validator.

A shared offline/SQL fixture assembler now builds that marked plan, full preview
and original request digest once. Its local preflight reports all failed
predicates together: frozen plan; registration/8 MiB bound; storage root, target,
allocation and freshness; retained anchor/expiry/deletion/write deadline;
eligible principal/target/identity and permission revisions; original recovery;
case/occurrence IDs; exact preview canonical scope and reviewed timing marker.
The offline assembled fixture passes. The actual fixture runs the same checks
before preview persistence/SQL admission, keeping protected observations and
original deadlines. These are test-only checks, no production port or validator.

The failed run's 3,271 hashes independently matched; sourceUnchanged=true,
cleanup [], exact `asservat-custody-m53hggn3-postgres`, `-s3` and network absent.
Archive before source edits:
`/home/phil/.cache/asservat-build/approved-workflow/policy102-recorder-focused-2-artifacts/`;
report SHA-256 48cab9576f7c548b763057e0d1158f9c97414231b04f489fbb2c1d40b9476b3f.
No actual recorder admission or negative action-pool result is claimed. Reuse
prior policy-share positives and require a reviewed focused rerun only.

Recorder focused run 3 at frozen f4a46cfe terminated exit 1 (Go 8.133 s,
harness 10.928 s). Full assembled preflight and persisted reviewed preview passed.
Positive admission then used the wrong fixture facet: hub-runtime intentionally
lacks storage-binding row-lock writes; actual production composition uses the
separate capture-admit purpose. PostgreSQL log lines 68–71 confirm its denied
ShareContextStorage FOR SHARE. Negative admission reached the intended ErrDenied,
then a fixture-only raw counter assertion referenced nonexistent
policy_collected_bytes_spent (actual schema name policy_bytes_spent), so its full
counter proof remains incomplete. No product authority/guard/privilege change.

The fixture now uses the existing compiled capture-admit role/pool and closes it
before cleanup, matching production. Grant counters use AccessGrants.Grant and
PolicySpend; accepted counters use PolicyTriggers.Status. The sole remaining
counter SQL is the existing bounded occurrence count. Facets compared against
public_context_compose.go and the closed compiled roles: policy-automation,
capture-preview and evidence-share/Grant share hub-runtime; capture-admit is
separate; protected approval settings stay under permission-accept. Existing
synthetic permission/bootstrap and separate source/accept/audit/read fixture
facets are unchanged. The current accepted/source read still precedes admission.
Offline assembled binding/compiler tests pass with race, actual exit 0, 1.079 s.

All 3,271 hashes independently matched, sourceUnchanged=true, cleanup [], exact
`asservat-custody-mki2bfyh-postgres`, `-s3` and network absent. Archive before edits:
`/home/phil/.cache/asservat-build/approved-workflow/policy102-recorder-focused-3-artifacts/`;
report SHA-256 0a386c93e17813b52772714983890123417fcdc8dae12ccd1bb2ed6428c1758c.
No automatic retry and no positive recorder admission/counter qualification yet.
The root coordinates the next external slot separately from h2's Kind work.


Recorder focused run 4 at frozen 6e12afa4 passed, actual terminal exit 0 (Go
9.272 s, component child 7.82 s; packet 4.15 s / snapshot refusal 3.67 s;
harness 12.032 s). Actual Tick pre-spent one accepted execution. Initial reviewed
packet admission and exact replay retained one 8 MiB OUTPUT RESERVATION in each
accepted/grant byte pool, one grant execution and one original reservation.
Snapshot-only authority/attachment refused the recorder with zero output/grant
reservations, retaining only the Tick execution. No packet acquisition, native
artifact production/publication or collector execution occurred in this fixture.
Reuse frozen f94be53c's 36.81 s policy-share/original-grant acquisition/revocation/
status pass; no repeat was run solely to change log wording.

All 3,271 hashes independently matched, sourceUnchanged=true, cleanup [], exact
`asservat-custody-yh9zl_ac-postgres`, `-s3` and network absent. Archive before edits:
`/home/phil/.cache/asservat-build/approved-workflow/policy102-recorder-focused-4-artifacts/`;
report SHA-256 ee995b179a26b5d390a34c52c8ab2a1a6fcbe1941b8f8a290e8f5d13e91e2fd8.
The host slot was released for h2; no further external run is authorized here.

ADR-261 is an engineering revision accepted under the maintainer's proportionality
instructions, not a maintainer choice of twenty seconds or download-rule reuse.
New admission/permit issuance/renewal still checks original fresh facts after
locks; already-issued work may start within its original shortened latestStart
and continue only to its original <=20 s leaf inside every reviewed/hard bound.
External source-change visibility retains its own lag; e.g. a qualified 5 s lag
plus a 20 s leaf can compose to 25 s, rather than a universal twenty seconds from
an external edit. An authoritative SQL grant revocation/recovery fence blocks
later issuance under existing locks. No connected packet stop is currently
implemented. Missing latest-start slack declines rather than extending a session.

The rejected three-second renewal loop would add about four SQL transactions,
four signatures and twelve RPC pairs per 15 s action (256/256/768 for 64 such
actions), or 21.3 transactions/signatures and 64 RPC pairs/s for 64 continuing
sources. A fitting finite action has zero renewal operations. Initial SQL/node
binding, both pool debits, bounded terminal state and native checks remain; the
provisional seven observation-specific statements and initial/provider latency
must be measured. Initial permit data uses the existing authenticated same-work
operation tied to the already signed capture/expectation; the current first
signature happens before later SQL preparation, so do not claim it signs future
permit bytes. No independent initial JWS operation is intended. No three-second
renewal machinery, new worker/watch/service/table/credential/config is added.

The corrected node-source contract before implementation uses one seven-field
C-24 targets.PacketSourceObservation: PodUID, NodeUID, BootID, CollectorPodUID,
CollectorEpoch and original ObservedAt/FreshUntil. RecorderAnswer.Source is optional
facts only; C-19 EnqueuePacketExpected consumes that exact value directly. The
catalog already permits C-19 → all C-24 domain types, and delivery → targets is
acyclic. The proposed duplicate collector.PacketSourceBinding/bootstrap mapping
was unnecessary and is removed before source edits. Enqueue checks cancellation,
original interval and exact tuple under its existing injected clock/mutex, with
no extra deadline timer, catalog change or freshness knob. ObservationBinding and
Permit move byte-compatibly to domain/collector, with a fixed canonical rule
digest checked against the version string in tests, without broadening the pure
domain crypto allowlist. LatestStart stays separate: new enqueue needs fresh
facts; already-issued work retains only its original start bound. Storage owns
this isolated source/node slice after the clean reviewed contract checkpoint.
This agent owns later policy-only SQL/issuer/C09 composition; manual raw and
longer finite/default ongoing modes remain unfinished.
The ADR/spec-only checkpoint passed spec-check, architecture-check and design-check
with actual exit 0 (176 requirements / existing scenario IDs retained). It makes
no runtime/schema/permission or raw-availability change. The primary lifecycle
precedents were inspected at their pinned source versions; they support the
admission/lifetime separation, not the engineering choice of twenty seconds.

Contract review checked the actual dependency catalog (C-19 → C-24; all
internal/domain owned by C-24), eliminating the unnecessary duplicate source
value/conversion before any implementation. The single source observation API
and fixed rule digest require no catalog/checker/permission expansion.

Finite SQL implementation cost checkpoint (after source/node b6d153df): the
observed requirement is pre-predicate input accounting for a sensitive policy
packet action; the ordinary metadata path does not need this row. One original
session per admitted capture adds one bounded heap row and three indexes, one
INSERT and at most one terminal UPDATE plus DELETE (<=3 transitions, no renewal).
The once-only grant/accepted counter debits serialize under existing authority
locks; uncertain replies recover the original row and never rearm/refund. New
preparation uses the same existing transaction and capture/expectation identity.
No new table, credential, provider connection, watch, worker, timer or user knob.
The node foundation's existing metadata response omits Source; only the explicit
source query returns facts, preserving strict older wire decoders.

The first prospective SQL additions are one session lookup, one active-session
COUNT, two guarded counter UPDATEs and one INSERT, plus database-clock checks;
these are SQL round trips, not zero network requests. Current original grant,
accepted source and locked eligibility checks remain, with exact counts to be
reported from the final composed implementation. Initial issuance uses no new
provider signature. Concurrent first attempts serialize on the existing capture
and grant/permission locks. Replay reads the original immutable tuple and does
not recompute duration/credit/latestStart. Epoch/source change cannot rebind it.

No global NativeRows 1->2 backing increase is made: ordinary metadata/manual/
download captures have no observation child, and that change would increase
aggregate native WAL units 30->44 (~47%) for unused capacity. The finite child
has <=3 transitions, within the existing ten-transition engineering envelope;
this does not prove its physical backing. The protected root metadata contract
already covers the complete ordinary context/control/publication graph per
capture (RecordRowBytes >=128 KiB, RecordWALBytes >=1 MiB). The next owned SQL
qualification must measure the complete sensitive graph plus new row/index/WAL,
including rollback/delete, against that accepted envelope before raw enablement.
Do not silently assume spare bytes or change historical qualifications. If it
cannot fit, use a purpose/plan-specific protected quantity, not a global ordinary
cost increase or renewal-WAL service.

Retirement belongs to the existing audited capture deletion finalizer: after
positive writer quiescence/backend purge, acknowledged deletion audit and the
same-transaction finalization claim/tombstone, delete that capture's session only
after its immutable lease end. Retrying cannot delete a different capture or
refund either observed pool. Unknown acquisition/completion remains charged and
retains its backing until that existing protected lifecycle can finish; an
elapsed lease alone is not writer/backend quiescence. No new sweeper is added.
Raw admission remains closed pending SQL, exact node transport, prefix and native
qualification. Manual raw and full ongoing-policy arming are separate unfinished
requirements, not authorized by this policy-only implementation checkpoint.

The implemented helper adds six round trips on first preparation: one original
session read, one original acceptance read (counter only), one live session
count, two observed-pool UPDATEs and one INSERT. Replay adds one session read,
no updates/session/start. Four initially drafted extra database-clock reads
were removed before qualification: preparation already reads current time after
its API row lock, and checked() repeats original authority/storage/clock checks
after the callback. The companion passes the original source cutoff as an independent ephemeral
effect deadline to that SAME check, so a wait beyond it rolls back all SQL
effects. Existing c.ValidUntil also enters persisted Binding.NotAfter, so it
remains unchanged: source freshness changes no preparation/scope/digest identity.
For a first insert only, the same temporary effect bound also clips to the
immutable new startBy before the final checks; post-effect waits cannot commit a
known unusable dispatch. Passive replay keeps the original expired receipt. INSERT
also checks source/start cutoffs using database time. The finite window anchors
the existing pre-helper timestamp (earlier is conservative), never a new time
on replay. Existing original occurrence/grant locks are reused without another
read chain. Count is acceptance-scoped under the existing permission lock, so
two grants cannot evade the shared session ceiling. No provider/API calls,
connections, signatures or renewable tasks are added.

New privileges are explicit: the existing api-execution duty gains SELECT/INSERT
on policy_observation_session and UPDATE only policy_acceptance.observed_bytes_spent
and access_grant.policy_observed_bytes_spent. It already reads the original
acceptance/grant and holds its id-only grant row-lock privilege. The installed
hub-runtime union receives these exact new effects; no fresh credential or
exported renderer for a retired standalone duty is introduced. Existing
context-cleanup-finalize gains DELETE and SELECT(root_id,capture_id) only on the
session table; its already-held checkpoint/attempt reads satisfy the deletion
trigger. This adds one bounded DELETE round trip per actual terminal capture
finalization, including a zero-row check for ordinary captures. Other cleanup
facets cannot retire sessions. No end/renewal UPDATE privilege is granted.

ObservationPermit now retains original StartBy and Duration alongside its
original lease/credit. Reconstructing a fresh latestStart from a replay clock
would extend dispatch, so those issued-work values must travel with the
immutable permit. This is an unpublished private contract extension; existing
local lease/meter semantics are unchanged. The companion preparer is not yet
called by the runner or transported by C09. The shared raw compiler refusal is
unchanged for manual and policy recording until complete qualification.

Finite SQL source checkpoint local verification (before external qualification):
make pre-push actual exit 0, including SQL generation, schema/spec/architecture,
Go vet and 231 console tests. Full affected race command actual exit 0:
postgres 2.589 s, bootstrap 54.614 s; execution, authorization, collector,
targets and delivery cached passes. Logs:
`/home/phil/.cache/asservat-build/approved-workflow/policy102-finite-sql-source-pre-push-final.log`
and `policy102-finite-sql-source-races-final.log` in the same directory.
New focused tests cover immutable SQL-row-to-permit replay, changed original
identity/program/accounting/credit/dates, unusable finite dispatch, original
source containment and exact role grants. These are local/pure component tests,
not real SQL, source-authentication, byte-prefix, backing or native evidence.
Next add actual generated-query rollback/immutable-row SQL markers, then genuine
companion held-wait and same-work transport tests under the still-closed gate.

Read-only review of 23ec0b8c found a concrete program-identity mismatch: SQL used
JSON SHA-256 while actual node work uses FilterProgramDigest's little-endian
8-byte classic-BPF instructions. The regression failed with actual exit 1
(0.010 s), JSON 22c379ad... versus node c80fe4c7.... SQL now reuses that existing
canonical function on the exact converted instructions; no new digest format or
compiler/cache is added. At most 256 instructions / 2 KiB are converted per
first preparation; this is a bound, not a CPU benchmark. Focused observation/
source/role races passed 1.063 s; final combined focused races passed postgres
1.074 s, bootstrap 4.082 s and integration compiler/bindings 1.084 s. Final
pre-push actual exit 0 including 231 console tests. Logs use absolute directory
`/home/phil/.cache/asservat-build/approved-workflow/` with names
`policy102-finite-sql-fixture-pre-push.log` and `policy102-finite-sql-fixture-races.log`.

The added packet-policy-observation-sql fixture is deliberately a separate nested
mode: existing ordinary packet/snapshot cases retain their original zero observed
pools. It admits a real ordinary header capture and uses generated queries with
explicit synthetic observation review/node/scope facts, never an application raw
permit. It checks actual held-table expiry/rollback with independently read zero
accepted/grant spend and no session; one finite committed tuple and exact SQL
read; fresh IDs/fence/dates cannot insert another session for that capture;
immutable credit/epoch, nonpositive/over-budget debits, and live-session expiry
without refunds. Compiled finalizer early and expired-but-unaudited deletion must
refuse. The sample row/relation/index and WAL values, when actually run, will be
reported only as SQL component samples, not a full-graph/worst-case/backing proof.
No actual external run of this new test has yet occurred. Genuine companion
held-wait, positive audited retirement, native bytes/prefix and backing remain
required before enabling the policy-only raw path.

Old-node wire audit (h2, pinned eed85940 / 6e12afa4 / b6d153df): NodePollResponse
uses nodeDecode -> decodeClosedRPC with DisallowUnknownFields and canonical
shape equality; an emitted unknown permit field, even null, rejects the whole
old poll. Client.Poll returns no work on decode error before DomainWork/start.
A legacy-shaped packetCapture with the field OMITTED remains unmetered, so the
future sender must emit a nonnil required raw permit and the new receiver/start
must carry/enforce it, with no omission/downgrade fallback. Image pinning is not
an app-meter capability check: current attestation checks Pod/DaemonSet/account/
node/boot, and reported engine version is Gadget. No new version/flag framework
is needed solely for this strict-decoder boundary. Actual old/new poll regression
and exact authenticated transport still precede raw availability.

Finite observation SQL run 1 at frozen 46e72285 terminated actual exit 1 (Go
21.463 s, harness 36.721 s). Migration Up/Down PASS 4.35 s (top-level proof in
raw Go log; the slash-filtered report list omits this top-level name). New
packet-policy-observation-sql child PASS 14.10 s: generated query held-table
source expiry CHECK23514 and independently read accepted/grant/session rollback
all zero; one 32 MiB conservative input reservation per original pool; immutable
original tuple/unique capture, debit bounds, active-count expiry and compiled
finalizer early/expired-but-unfinalized refusal. Sample tuple 528 B, whole current
observation relation/indexes 65,536 B, global WAL delta including debit/insert/
negative writes 9,480 B. These are partial component samples, not the complete
sensitive graph/worst-case backing or actual companion/node/raw qualification.
No packet acquisition, native bytes or positive child retirement occurred.

The selected compiled-publisher case failed earlier at 2.53 s: an old negative
facet expected shared hub-runtime to lack custody_copy.etag UPDATE. ADR-255's
existing capture-history duty intentionally adds that column update to the hub
union. The eight remaining negatives were compared against the complete current
compiled union: execution DELETE/binding mutation, capture INSERT/expectation
mutation, recovery clear, catalog INSERT, context-key unwrap INSERT and authority
audit DELETE remain excluded. The fixture now retains those denials, replaces the stale etag denial with
custody_copy.attempt_id UPDATE (the real excluded identity column), and separately
requires the existing history etag update, each WHERE false (no data mutation).
The narrower execution-duty unit contract still excludes custody-copy writes;
no retired duty renderer or product privilege change is added. No ordinary
positive finalization result is claimed from the failed publisher child.

Archive before source edits:
`/home/phil/.cache/asservat-build/approved-workflow/policy102-finite-observation-sql-1-artifacts/`.
Report policy102-finite-observation-sql-1-environment.json SHA-256
fe15c8b328f2c4ccc26439a38065a3fc07159e5fb309e47a9e3be5a4a9a93c32;
raw Go/publisher/migration log is the same prefix.log. All 3,280 source hashes
independently match frozen commit and disk; sourceUnchanged=true, cleanup [],
exact asservat-custody-lf54jl01-postgres, asservat-custody-lf54jl01-s3 and
network asservat-custody-lf54jl01 absent. Independent source/absence
JSON and actual runner terminal metadata are in that archive. The host slot was
released to root/h2. Reuse marker/migration positives; no automatic rerun.

The corrective fixture review read ADR-222's accepted ordinary process union,
ADR-255 and the actual custody_copy DDL/query paths. attempt_id is a real foreign
key and part of the row primary key. No custody_copy row-immutability trigger
was found; the history duty legitimately updates its receipt columns. Therefore
this WHERE-false regression establishes the compiled column privilege boundary,
not a proof that all evidence/receipt writes are impossible. Existing completed
result verification, separate publication/key/delete/recovery effects retain their
own guards; no role/pool or extra product mechanism restores the obsolete test.

Corrective fixture local checks passed with actual exit 0: pre-push (231 console
tests) and integration compile/offline compiler/bindings race 1.081 s. Logs:
`/home/phil/.cache/asservat-build/approved-workflow/policy102-finalizer-fixture-fix-pre-push-final.log`
and `policy102-finalizer-fixture-fix-compile-final.log` in that same directory.
Only the failed compiled-publisher child needs a reviewed focused external rerun;
no unchanged marker/migration or prior packet/snapshot/share/public suite repeat.

Focused publisher rerun at frozen 1a77e93a passed, actual terminal exit 0 (Go
6.711 s; compiled-publisher 5.26 s, nested deletion due-pages 0.04 s; harness
16.793 s). Real API preparation/result verification/publication and audited
ordinary capture deletion now pass with the new zero-row observation DELETE.
This proves the ordinary finalizer regression, not positive observation-child
retirement. No unchanged marker/migration or packet/snapshot/share/public suite
was repeated. Existing prior component positives remain reusable as scoped.

Archive before edits:
`/home/phil/.cache/asservat-build/approved-workflow/policy102-finalizer-focused-1-artifacts/`.
Report policy102-finalizer-focused-1-environment.json SHA-256
f98ed648313fa4766d2ccad77bc2c15085ee1f2e32d29dba21a635262b1745d0;
raw Go log is the same prefix.log. All 3,280 source hashes independently match
commit and disk; sourceUnchanged=true, cleanup [], exact
asservat-custody-yxk0bukn-postgres, asservat-custody-yxk0bukn-s3 and network
asservat-custody-yxk0bukn absent. Independent hash/absence and actual terminal
metadata are archived. The host slot was explicitly released to root. Next:
genuine companion held-wait and positive child retirement, authenticated exact
source/permit channel, complete graph backing, packet prefix/native qualification.
Raw remains closed; no first SQL component result substitutes for those gates.

Next companion qualification slice: the shared manual AcceptableRecorder raw
refusal currently prevents even an inert policy frozen expectation/API check.
Use a private policy-only structural acceptance path in existing context/recording
derivation, selected by the installation-local policy executor. It supports one
onTrigger packet action, before 0, actual duration <=15 s and original reviewed
observation limits; it grants no authority or permit. The ordinary/manual shared
AcceptableRecorder remains unchanged, as do runtime trigger and C03 raw refusals
until authenticated SQL/node/prefix/backing/native composition qualifies. This
adds no API/SQL reads, watch, task, config, credential or compiler pass: it consumes
the same already compiled plan in O(1) for this single-action profile. It addresses
the concrete inability to qualify the actual companion without synthetic checks.

Recording.RequireApproval is the frozen protected require-all setting, not a
sensitivity override. Reusing it for raw need would add a different approval
reason on replay and alter scope. Policy SQL admission/original-grant effects
instead derive grant necessity from the actual frozen raw predicate as well as
that existing setting, and require a positive reviewed observation pool before
output reservation. This is a pure check of the already-read grant/plan, with no
new round trip or identity/approval field. ObservationPermit.ValidFinite shares
the original start/full-duration structural checks for SQL receipt decoding and
future transport/start; standalone construction supplies no authority.

Inert compiler/consumer checkpoint: actual unit RED (0.002 s) could not derive the
policy frozen expectation; new policy-only structural path passes exact scope/
setting/program roundtrip while manual raw still refuses. Legacy regional raw
start RED actually queued one work item (0.013 s); the new refusal passes before
prepared ownership/queue changes, leaving caller Close available. The single
canonical binding now requires ProgramDigest and ExpectationDigest (no weaker
prototype branch); SQL copies the already-stored canonical facts, and mutation
of either invalidates the local bound session. These remain non-authority values.

Independent storage read-only review found no concrete blocker in these source
changes. Final pre-push actual exit 0 incl 231 console tests; complete affected
races actual exit 0: planning 1.220 s, capture 11.237 s, execution 1.304 s,
postgres 2.648 s, collector 1.007 s, bootstrap 54.595 s. Logs:
`/home/phil/.cache/asservat-build/approved-workflow/policy102-inert-policy-compiler-pre-push.log`
and `policy102-inert-policy-compiler-all-races.log` in the same directory.
No new external run, runtime raw gate, C09/node wire or native qualification.
Actual companion held-wait and positive-child retirement remain next, followed
by authenticated transport, complete graph backing and packet prefix/native.

Genuine companion fixture source checkpoint: a separate packet-policy-companion-sql
mode now builds a real accepted policy/occurrence/grant and frozen raw context
through the shared assembler, with actual companion checks before each effect.
Node/process/target/bootstrap/reviewer facts remain explicit synthetic component
inputs; runtime trigger/C03 raw gates stay closed and no packet engine runs.
Preflight reviewed roles: separate existing capture-admit for admission, existing
hub-runtime union for API/current team/grant/observed SQL, existing separately
credentialed capture_audit_runtime for acknowledged encrypted capture intent
(same component facet as the qualified API fixture). No hub audit privilege gain.

The actual test will hold the ORIGINAL grant row beyond the original shorter
source cutoff while the original caller/identity check remains live, then
independently read absent API/session and zero observed spend in both pools.
A fresh actual companion preparation must create exactly API1/session1 and
32 MiB conservative credit per pool; stored Binding.NotAfter must remain the
original API check deadline, not the shorter source cutoff. Exact replay is
passive with identical binding/permit/dates; a replacement collector epoch under
still-live original facts must refuse without changing either pool or row.
This tests actual adapter authority/transaction composition rather than manually
inserting a marker, but does not qualify authenticated node facts, transport,
positive child retirement, full graph backing or native/prefix behavior.

The raw fixture is exact tcp[13] & 2 != 0. The local real static libpcap 1.11.0
compiler independently matched its dead EN10MB/snaplen65535 eleven-instruction
program, canonical digest c7cde9898f21dcab2b5000d3c62eb24f7b8222fda01149221d900ea9c78c4a2f;
actual exit 0 / 0.013 s, no device/socket/collector. Both header and inert-raw full
assembler preflights pass with race (1.094 s), final pre-push actual exit 0 incl
231 console tests. Logs in absolute directory
`/home/phil/.cache/asservat-build/approved-workflow/`:
`policy102-genuine-companion-native-compiler.log`,
`policy102-genuine-companion-offline.log`, `policy102-genuine-companion-pre-push.log`.
The new actual SQL test has not yet run; require reviewed frozen exact selection
and coordinated host slot. Prefix/notice components remain separately qualified
pure components, not raw execution enablement.

Genuine companion run 1 at frozen bc5aae8b terminated actual exit 1 (Go 5.304 s,
harness 32.117 s). Actual held original-grant source-cutoff test passed: original
caller/check still live; independent API/session absent and both observed spends
zero after rollback. Fresh positive companion failed at effect/observation, so no
positive/replay qualification is claimed. PostgreSQL log contains only expected
negative-role errors, no new observation SQL error.
Archive before source edits:
`/home/phil/.cache/asservat-build/approved-workflow/policy102-genuine-companion-focused-1-artifacts/`;
report policy102-genuine-companion-focused-1-environment.json SHA-256
46503319328f4ac473feab93c5229b81790aa5793c56abdc331c45358a171829,
raw same-prefix .log and provider -postgres.log retained. All 3,282 source hashes
independently match frozen commit/disk; sourceUnchanged=true, cleanup [], exact
asservat-custody-32pc3krl-postgres, -s3 and network absent. Host slot released.

The concrete production defect is scope serialization: pgx v5.11.0 binary
TimestamptzCodec uses time.Unix/time.Local and MarshalJSON retains that zone,
while the row was hashed before INSERT in UTC. Identical instants could fail
scope decoding after RETURNING. A deterministic actual pgx binary Encode/Scan
non-UTC witness failed RED (exit 1, 0.010 s), explicitly checking Equal instants.
The fix normalizes only all six timestamp representations to UTC on the by-value
row before hashing. Stored columns, instants, original source/start/lease bounds,
API preparation identity, credit and caller intervals do not change. No I/O,
clock/read, compatibility branch or authority relaxation is added. This is the
unpublished/unwired permit path, not a rewrite of real historical receipts.
Focused observation/raw tests pass race 1.061 s; final focused adapter/offline
races actual exit 0 (postgres 1.087 s, integration 1.097 s) and final pre-push
actual exit 0 including 231 console tests. Absolute log directory
`/home/phil/.cache/asservat-build/approved-workflow/`: `policy102-companion-utc-fix-pre-push.log`
and `policy102-companion-utc-fix-races-final.log`. Require one reviewed frozen
companion-only rerun; no automatic repeat or other source composition first.

Genuine companion focused run 2 at frozen d9f6652e passed actual terminal exit 0
(Go 6.550 s, exact child 5.10 s, harness 23.808 s). Actual held original-grant
source-cutoff rollback leaves API/session absent and both observed spends zero
while original caller/check remain live. Fresh actual companion creates API1/
session1 and 32 MiB INPUT RESERVATION per pool; canonical program/expectation,
original start/end and original preparation NotAfter match. Exact replay is
first=false and unchanged; still-live-fact collector epoch replacement refuses.
No raw acquisition/native bytes, real node/process attestation, positive child
retirement or complete graph backing is established by this component fixture.

Archive before edits:
`/home/phil/.cache/asservat-build/approved-workflow/policy102-genuine-companion-focused-2-artifacts/`;
report policy102-genuine-companion-focused-2-environment.json SHA-256
d93569fbc719f95e10a7272647ae2f83180576dbf5cccaf5ac3d8349b1a31ed9;
raw same-prefix .log, terminal and independent hash/absence JSON retained. All
3,282 hashes independently match frozen commit/disk; sourceUnchanged=true,
cleanup [], exact asservat-custody-75j4f1sz-postgres, -s3 and network absent.
The host external slot was explicitly released. No unchanged marker/migration/
publisher/packet/snapshot/share/public suite repeats. Continue reviewed prefix/
input-notice components, authenticated typed source/permit holder/node channel,
real positive child retirement, backing and native qualification with raw closed.

Typed finite source/start composition checkpoint (2026-10-28, component): reuse
one same-work source operation instead of resolve-pod, and one typed start instead
of ordinary recording start: zero additional C09 exchanges, SQL queries or new
remote service/provider connections beyond the already recorded companion's six
first-preparation queries / one replay read. No new timer, watch, worker, table,
credential, config or fallback. The existing preparation gate wraps the companion;
first=false still returns before keys and queue effects. Original API preparation
identity/deadline is unchanged. The regional holder keeps the original source and
receipt, proves the frozen program fits134B, and enqueues without another Pod/node
API lookup. Prefix validation costs the measured 0.55us11-instruction /9.3us256
full check once per policy compilation/start, not per frame. All raw trigger and
manual refusals remain closed; no acquisition qualification is claimed.

The typed node foundation38ec3e4 is reviewed and composed as63305502. Ordinary
nil observation wire is unchanged. A finite raw work item emits a mandatory typed
permit; invalid decoding cannot downgrade to nil. Queue mutation clones program
and permit and checks original StartBy and exact authenticated node tuple under
its existing mutex. Actual measured maximum16-item/256-instruction JSON poll is
227243B under unchanged262144B. Node execution/meter and actual old/new TLS decoder
proof remain a separate component. Initial signed work independently binds the
expectation; the C09 start compares the receipt with that verified digest and the
locally retained source, not two caller DTO copies. No independent initial JWS.

Typed source/holder local verification: pre-push actual exit0 including231 console
tests; affected execution race1.303s, contextstart10.822s, bootstrap54.820s pass.
The initial execution test assertion incorrectly inspected the deliberately opaque
outer error; it was corrected to inspect the existing typed inner check step.
No authority behavior was changed to satisfy that assertion. Logs in the absolute
approved-workflow cache: policy102-typed-source-holder-pre-push.log and
policy102-typed-source-holder-races{,-final}.log. The direct receiver/holder tests
use synthetic verified-work/source/permit inputs and do not qualify an end-to-end
runner, actual node, encrypted output, retirement or backing.
Final same-source follow-up checks pass: execution race1.300s / C09 race10.795s
after preserving the retained source against a legacy resolve overwrite and
labeling its fixed diagnostic correctly; final spec/architecture/Go architecture
(67 packages/402 internal edges) and vet all actual exit0. Absolute logs
policy102-typed-source-final-c09-races.log and policy102-typed-source-final-checks.log.
No external fixture or collector ran for this source batch.

Prepared actual holder/retirement fixture candidate (not externally run): the
same companion child now samples the closed31-table graph before policy creation,
uses its original first=true receipt to prepare actual encrypted output, queues
through the actual expected-source NodeChannel, polls exactly that work and
routes one synthetic PCAPNG through the actual holder/producer. The maintained
recorder constructs SYN frames with the exact reviewed11-instruction program;
this is synthetic input with no collector, Gadget or live observation measurement.
Node attestation and certificate issuance remain explicit synthetic interfaces;
this is not actual TLS/Pod attestation or installed C09 qualification. The original
source and check remain live at start; no refresh/reissue occurs between receipt
and queue. Completion refreshes only the same process/recovery facts.

Only after actual stored completion and SQL acknowledgement does the reviewed
retirement helper run: restrictive retention, actual complete backend purge,
separate signed/encrypted deletion audit acknowledgement, early rollback, natural
original lease expiry, wrong-transaction refusal, then exact narrow finalization.
It retains the original API receipt and both conservative input spends. A fresh
synthetic caller preflight then exercises the actual companion's terminal refusal
and independently checks zero children, one stored receipt and unchanged spends.
The existing held-row cutoff/replay/incarnation assertions remain in this one
capture; no second capture is manufactured for the lifecycle matrix.

Whole-graph tuple counts, relation/index/TOAST sizes and global fixture-inclusive
WAL edges remain explicitly UNQUALIFIED component samples: this fixture seeds raw
pools and has no accepted protected RootMetadataQualification. No comparison to
minima, native-byte overhead estimate or supported backing guarantee is inferred;
largest accepted identities/program/composition and installed backing remain open.
This candidate changes test fixtures only after reviewed holder df877458 and
retirement helper34f8d678 (composed2cf49384); no production role/query/limit change.
Local final offline raw/header admission and synthetic-program races pass1.092s;
pre-push actual0 including231console. Absolute logs in approved-workflow cache:
policy102-typed-holder-retirement-preflight-final.log and
policy102-typed-holder-retirement-pre-push.log. Await one reviewed frozen owned
PG/S3 run of the existing exact companion child; no broader repeat or collector.

Actual owned PG/S3 typed-holder/retirement focused1 at frozen b6dfc7f3 PASS:
terminal runner0, Go16.481s, exact companion child15.03s, harness invocation
27.258s (reported test command19.264s). Only the reviewed three-level companion
selection ran; no collector or unrelated suite. Actual original-grant held-source
rollback, immutable replay and epoch refusal remain positive. Original first=true
receipt queued through the real expected-source channel, then4592B SYN-program
synthetic PCAPNG flowed through actual encrypted producer/store and SQL writer
completion ACK. Node trust/start facts and packet input remain synthetic; this
is not C09 TLS, native Gadget input or live observation measurement.

Actual legal purge and separate signed/encrypted audit ACK pass. Unacknowledged
finalization and acknowledged early finalization refuse with unchanged releases;
after natural original lease expiry a direct wrong-XID DELETE refuses. The narrow
actual finalizer retires child1->0 exactly once, keeps original stored API metadata
and both32MiB conservative INPUT RESERVATIONS, and releases only the custody
charges specified by the existing finalizer. A new fresh synthetic caller preflight
then reaches the actual companion's terminal refusal, independently leaving zero
children, one stored receipt and unchanged spend. No second capture or receipt is
manufactured; native output reservation remains8MiB, distinct from4592B synthetic
PCAPNG bytes and from unmeasured observed input.

The closed31-table UNQUALIFIED sample records stored29logical rows/23284tupleB,
purged+audited31rows/26284B, retired31rows/25724B. Fixture-global WAL edges are
621792B before-policy->stored,9016B purge/audit/refusals,1968B final retirement;
rollback/FPI/shared fixture writes are included, not attributed application cost.
Entire shared heap/index/TOAST relations total1744896B then1810432B; these are not
per-capture bytes, reclaimed disk or accepted backing. Observation row608B and its
relation/index pages remain physically allocated after logical deletion. No
protected qualification, maximal256-instruction/identity/composition graph or
installed performance claim follows. Existing backing quantities/transitions and
ordinary capture costs stay unchanged; those qualification gaps remain open.

Archive before any edits:
`/home/phil/.cache/asservat-build/approved-workflow/policy102-typed-holder-retirement-focused-1-artifacts/`;
report policy102-typed-holder-retirement-focused-1-environment.json SHA-256
791a459aacf01472c4a46660572b64800e525faabaa2d1efa8d642c1cc61e6a8;
raw log, actual terminal, independent hash and owned-absence JSON retained.
All3293 source hashes independently match frozen commit/disk,
sourceUnchangedDuringTest=true, cleanupFailures=[], exact
asservat-custody-0dajlewo-postgres/-s3 and network absent. Generated results were
archived before removal, source freeze and external slot explicitly released.
Next compose reviewed node enforcement/strict old-client proof and qualify actual
source/C09/node/prefix/loss/lease behavior plus protected backing/native workflow;
keep raw trigger/manual/ongoing gates closed until their respective paths qualify.

Post-archive C09 framing component: an actual bounded hub/regional conversation
now roundtrips the new exact-source and typed-start operations, the frozen
expectation comparison, committed start, finish echo and receipt. Exact original
permit succeeds; tampered program refuses before recorder dispatch; no source
refresh or ordinary fallback occurs. Verification/start/output doubles remain
synthetic, so this adds no TLS, signature, SQL or installed authority claim.
Focused race passes1.070s; absolute log approved-workflow/policy102-finite-source-stream.log.
No production code/query/permission changes and no external run for this test.

### Unpublished assembled finite-policy qualification candidate (2026-10-28)

Maintainer-authorized sequencing removes the policy-only trigger/C03 raw
placeholder after original-grant SQL, typed same-work C09 and node composition;
it adds no bypass/flag. Manual/public ad hoc raw remains unavailable, ordinary
API preparation and legacy raw StartRecording still refuse, ongoing raw remains
unsupported. The private accepted-settings provenance, exact frozen scope,
original grant, positive observation review, both prepaid pools and mandatory
committed permit remain independent gates. A finite private-policy producer RED
(`policy102-finite-policy-producer-red.log`) reached the former placeholder;
focused GREEN1.151s and capture races11.219s follow its removal. Existing seven
composed package results are retained; node44's component full matrix is not
presented as proof of the current assembled head.

Node replay RED established that same-epoch re-enrollment resets its poll cursor
and could create another meter for one capture. Corrected9e9f91be composition
claims captureID atomically with budget/meter under existing budgetMu, at most64
entries, logically valid only until original StartBy, lazily pruned on the next
sensitive start; a full cache returns existing CaptureBusy. No timer/watch/API or
per-frame cache work. Unmeasured amd64 payload estimate:64*(36UUID bytes +16string
header +24time bytes)=4864B, order16KiB with map/allocator overhead, not a measured
or hard heap bound. At most64 deadline comparisons plus one lookup per sensitive
start. Expired physical entries can remain until next pruning/process exit,
while cardinality remains bounded. Replayed/conflicting fence/full/expiry tests
pass, and input permit/program values are cloned rather than caller aliases.

Late/final loss or unknown input could also be masked by a provider's normal
context/deadline result, including unknown after the gate had first recorded its
normal deadline. Reproduced REDs now retain ErrObservationClosed for unknown and
non-deadline meter refusals over nil/provider cancellation/deadline. A genuine
provider failure, including cancellation, remains an error when the only meter
stop was its natural deadline. Ordinary nil-meter behavior stays covered.
Final component9e9f's actual old/new Client.Poll TLS proof returned four real
HTTP200 responses: two legacy positives, old strict decoder refusal with zero
work for the emitted permit and new valid permit retention. Full44 code gate
passed66packages/663Kubernetes tests; final9e changes only the bounded proof-output
helper after a real io.Copy/command cap RED. Root independently verified its
11888 source hashes and proof logs; report SHA-256
5a3f0cd11fc7e230a24b326a24007a00793c06ec27fe371d11f076f24d6fe1db.

History/pacing7254 and storage-expiry e3bf1ea9 are merged without runtime
conflicts; progress-document conflicts preserve both incoming and S04 evidence.
A real merged Python harness NameError referenced retired approved_recording;
separate946932d0 fixes the actual main report expression. Four-scope expression
RED, selector GREEN21tests and original failure logs are retained. This was a
merge defect, not a product authority change. Storage expiry recovery retains
original cutoffs; no new SQL role/limit is added by these compositions.

The new guarded continuation-policy-recording focus reuses existing two-cluster
installer, published digest-pinned Gadget, reviewer and native-download helpers.
Harness and workflow require the disposable-host guard before setup/collector;
job20m and Go18m remain unchanged. No local collector run is permitted. The focus
uses two real onTrigger restarts: one original1B input-credit refusal, then a new
independently reviewed grant after creator departure/current sponsor attachment
replacement and original-grant revocation. It waits the first lease naturally,
never resets pools. The second2s action conservatively prepays48MiB input
(16MiB/s*(ceil2+1burst)), distinct from128MiB reviewed grant,16MiB cumulative
output reservations and actual retained delivery bytes. No extra production
observer/renewal/watch/credential/service or user configuration. Additional
requests/reviews/traffic/status reads belong solely to this qualification.

The ACK expression tcp[13] & 16 != 0 is emitted by the maintained libpcap1.11.0
dead-handle compiler, not instruction edits. Actual tagged equality race1.362s
passes against its complete11-instruction JSON fixture, canonical program digest
d0679198c133da149f21a13ed2aaf9600ea8e23403797fcef51154ece1bdf93e;
88B access proof fits134B node prefix. No device/socket/collector was opened.
Pure preflight caught another genuine defect: requested15s session was schema
valid but exceeded the authored10s review ceiling. Actual RED is retained in
policy102-native-session-review-red.log; request is narrowed to10s, with action
and48MiB allowance unchanged. Native field parser preserves the trailing empty
payload column and rejects payload/non-ACK/malformed rows. Authored-input/focus
races pass1.344s; these are preflight, not installed/native evidence.

Planned installed assertions include real public independent review, team
continuity, both original session credits, native stored publication and exact
hash/download plus offline tshark ACK-only headers/no user-data payload. A bounded
policy-recording-report.json is written only after those checks succeed. No
installed pass is claimed. The existing protected native metadata input declares
128KiB record rows/8MiB record WAL; prior raw-pool graph samples remain UNQUALIFIED.
Largest identity/program/composition and accepted whole-graph/backing comparison
remain separate open qualification work; no global row1->2 or limit increase.
Manual raw, full ongoing/session renewal and syscall composition remain unfinished.

Native partial measurement uses five additional fixture-only SQL round trips:
initial global WAL LSN, one real capture/allocation/pool plus protected metadata
projection, existing sample LSN/31-table UNION, and global WAL difference. The
baseline precedes policy creation; it has no invented allocation or tuple-row
baseline. The final sample includes both real attempts and all shared fixture
activity/background writes. It records actual protected Metadata alongside the
sample without attributing global WAL to one record or treating entire shared
relation pages as capture bytes. No new production query or role is added.

Known tables outside that31-table sample include operation_audit_pool,
operation_audit_account, operation_audit, operation_audit_lifecycle,
operation_audit_history (separate purpose lanes), capture_audit_root,
capture_audit_allocation, capture_audit_binding, processing_root, processing_rule,
processing_decision, context_processing, artifact_download, download_allocation,
download_batch, download_key_binding, download_response, download_window,
download_control_allocation, download_native_backing, download_native_owner,
download_native_key, download_stop_pool, download_stop_backing, download_stop,
download_stop_lifecycle and download_stop_history. Their independently backed purpose costs must not be
silently charged twice to ordinary RecordRowBytes or silently omitted from an
entire-workflow claim. Protected capacity_source/root and capacity_workload
fixed/account graph is also outside this sample. Current sample is not a complete
catalog of all installation state. Remaining maximum-shape work includes256BPF
instructions,32audience assignments (issuer2048B/subject256B/basisUID64B),64retention
rules and original64B target/provenance identities within existing canonical
scope/expectation limits. Native's short ACK case does not prove those maxima.

Final composed local affected races after e3 merge: capture2.615s,
postgres1.265s, integration5.270s, actual exit0. Final native authored/selection/
parser/fixture-shape races after the report/sample code pass1.623s, actual0.
First pre-push exit2 found only gofmt on the new report map; retained unchanged
failure log, formatted and reran the actual complete pre-push: exit0 including
all gates, go-vet, SQL/spec/architecture and231console tests. Logs:
policy102-composed-expiry-focus-races.log,
policy102-native-focus-final-races.log,
policy102-native-candidate-pre-push.log (failure),
policy102-native-candidate-pre-push-final.log (actual complete0).
Final broad Go/installed runs still pending source freeze and root coordination.

Root review found a qualification false-positive in the first native1B attempt:
public Failed + SQL captureFailed + credit1 could also arise from unrelated
source/node/provider failure. The follow-up keeps those assertions and now
requires the exact existing node log `node collector: capture <originalID>
stopped: ObservationBudgetExhausted` from the SQL receipt's original collector
PodUID and NodeUID. Fixture selects only the existing asservat-node label in the
owned regional cluster (bounded64Pod list, refuses pagination), pins original UID
and assigned Node before/after the log read, and checks NodeUID again on success.
No production logger/telemetry/permission/query is added; existing session SELECT
returns two more immutable identity columns. Read is capped64KiB/256lines and30s
of existing one-second wait polling: conservatively at most31attempts/93Pod+log reads plus
one list/twoNode reads, fixture-only. Generic failure, source/provider error,
wrongcapture and reason suffix fail the pure evidence check. The native attempt
itself remains unrun; the report records budget exhaustion only after this exact
proof succeeds. This corrects evidence semantics without changing runtime gates.

Final native creator-departure evidence now reads back the exact Keycloak user
immediately after enabled:false PUT, requiring the original subject ID and an
explicit enabled:false field (missing field refuses). One additional fixture
administrator GET, no product authority/read/observer change. A successful PUT
alone is no longer reported as verified creator departure; actual installed
execution remains pending. No whole pre-push repeat for this fixture-only check.

### Production DebugPolicy structural CRD correction after native failure

Native40648562303 at af9 stopped before grant creation: the real API warned
unknown spec.profileComposition and rejected required spec.recipeRef. This is a
production chart contract defect, not evidence of packet admission/execution.
The canonical policy schema already has mutually exclusive recipe/composition
branches and the finite policy compiler consumes profileComposition. The old
hand-reviewed ADR228 CRD never gained that field and required recipeRef globally.
No permissive test-only CRD or alternate authored request is substituted.

The shipped CRD now declares the bounded composition and enforces exactly one
recipeRef or profileComposition through structural oneOf required branches.
Existing recipe policy shape remains valid; both/neither,9components,33overrides,
unknown field tags and excessive total bytes refuse. A small synchronization
script owns only this projection inside the existing hand-reviewed CRD; it derives
component/ref/bounds and all21 override tags from canonical contracts. Existing
other detector/target properties remain unchanged. policy-schema-check and
helm-check verify this projection before their existing gates; there is no new
runtime process, admission webhook, provider request or configurable mechanism.

Kubernetes structural schemas cannot express a single property's heterogeneous
string/integer/object/array type union. Only override.value preserves original
JSON, like existing typed detector options; whole spec/composition/component
objects stay declared structural fields. The existing production source reader
first enforces its64KiB spec limit and the full closed canonical field-specific
schema, then the compiler/independent acceptance/grant pipeline. A wrong typed
value is still rejected before authority. No value is converted to a string or
silently pruned, and no weak compatibility branch is added. Full profile catalogs,
ongoing execution and unsupported composition variants do not become executable.

Complexity/benefit: one observed installed failure blocks every composed policy;
no maintainer accepted this contract mismatch. Correcting the existing accepted
workflow helps typical composed policies; doing nothing or authoring a fake
recipeRef cannot satisfy the actual compiler contract. Standard structural
pruning and the existing canonical validator supply the checks. Zero added
credentials, SQL/API calls, watches, workers, timers or runtime configuration.
CRD JSON grows13415->18706B (+5291B); native oneOf checks two required alternatives
per write. Composition remains at most8components/32overrides each, canonical
reader64KiB unchanged. No new end-to-end CPU/throughput claim; no quota increase.
Fresh chart installation includes the corrected schema. Existing installations
use the documented administrator-owned CRD apply before code upgrade; Helm
does not upgrade CRDs. Chart rollback must not imply CRD rollback; restoring
the old schema would again reject composed policy writes, without changing
accepted SQL, spend or evidence. Actual upgrade/rollback API behavior for this
correction remains unrun. No migration/table/collection gate is altered.

Meaningful local RED uses the exact installed authored builder against the
actual shipped CRD: test exit1/.015s, missing recipeRef. The corrected structural
schema plus canonical-reader closure pass local race tests. A cached upstream
Kubernetes v0.37.1 checker independently uses NewStructural/ValidateStructural
and actual pruning to verify mixed JSON values survive unchanged; no repository
dependency, network, API server or collector. This offline proof is distinct
from the pending actual API/installed rerun. Prior native/source/log evidence
remains intact; af9 PR103 tree is untouched by this isolated correction.

The same parity review found the only other absent canonical field, grantRef,
in both recipe/composition branches and the accepted compiler. It is now derived
as the existing UUID type, so authored A->B->A grant-reference changes survive
storage for existing continuity checks. A separate missing-property RED exit1/
.020s is retained; no new grant creation or authorization semantics is added.
Final CRD size18834B (+5419B versus af9), including that field. The prior5291B
figure records the composition-only intermediate, not the final artifact.

The initial pre-push exit2 was solely the isolated worktree's missing web
node_modules/yaml dependency; all other gates including Helm and go-vet ran to
completion. The exact matching existing package.json/lock dependency tree was
reused temporarily without installing or accessing a network, then the console
target passed231tests. Failure and corrected console logs are retained separately;
this is not an initial complete pre-push0 claim. Final checks bind the final code
and schema; no hosted/API/collector rerun is authorized or performed here.

Final affected authored/production-CRD tests pass -race1.467s, actual exit0,
including the grantRef projection. Final complete pre-push exits0, including
SQL/vet/spec/architecture/Helm projection and231console tests. No broad Go matrix
or external fixture was repeated. The Go regression alone checks JSON Schema and
declared properties, not actual Kubernetes pruning. The separate cached-upstream
scratch checker invokes real NewStructural/ValidateStructural and pruning with
string/integer/object/list values plus grantRef; its exact source/module/binary,
old/final CRD inputs, actual terminal exits and outputs are archived in
approved-workflow/policy-crd-structural-check. Old shipped artifact loses the
composition under actual pruning (expected failing exit2); final retains every
input unchanged. No API installation/upgrade, compiler/runtime acquisition or
installed pass follows from this separate offline structural/pruning proof.

## Protected metadata shape witnesses (2026-10-28)

The owned `policy-metadata-backing-5` fixture passed the exact selection
`^TestPolicyMetadataBackingWithRealPostgres$` on frozen test/runtime source
`0060ff581c0422f162323c1ab5fb3f1393eb96e9`: actual exit0, Go17.001s,
selected test15.94s, outer25.090s. It reused the existing custody runner with
`--fleet`, libpcap only, Go300s/harness360s/outer1100s; no collector/Gadget/device
ran. Static libpcap1.11.0 compiled on a dead EN10MB handle. Actual initial
activation, protected capacity setup/enrollment, narrow managed admission and
original MAC/capture audit roles, policy acceptance/independent grant review,
Tick, finite SQL permit, typed channel/holder, encrypted synthetic PCAPNG writer
and stored ACK were composed. Control/node/process/packet inputs remain synthetic.

Both SQL cases used64 accepted retention source identities/60 definition digests;
their legal varied specs used the actual schema decoder/canonical digest helper.
The audience case used32 current audience assignments; the program case used1
and an actual prefix-safe254-instruction program. The separate offline program
probe used1 retention source, so its smaller arithmetic size is not this SQL
combined shape. No Cartesian maximum over all allowed inputs is claimed.

| Actual SQL case | Scope / expectation bytes | New ordinary record tuples / allowance | Cumulative record tuples / occupied allowance | Shared account tuples / allowance | Mixed global fixture WAL |
|---|---:|---:|---:|---:|---:|
| audience-retention |14684 /62792|71624 /131072|71624 /131072 (1record)|10676 /262144|621744|
| program +64retention |19210 /26697|52163 /131072|123787 /262144 (2records)|23022 /262144|518696|

Fixed tuples were458B against1MiB. Per-record measurements use nonnegative
before/after tuple deltas, including `policy_occurrence`; cumulative totals use
actual occupied capture count. Shared source/grant parents are counted once in
the account sample. The32-table sample labels ordinary versus separately paid
lanes; capture/native/Stop/processing graphs outside it are not silently added to
ordinary128KiB or claimed measured. Entire shared-relation heap/index/TOAST
figures are labelled, not attributed per capture. Global WAL includes fixture
activity, not isolated ordinary-record cost; primary RecordWALBytes is8MiB,
not multiplied by WALCopies3 to make a comparison pass.

Selected protected metadata matches the installed profile's128KiB record row,
8MiB primary record WAL and backup/WAL copies2/3, with actual accepted SQL JSON
readback. The fixture retains16accounts×3records=48; the native profile has
16×4=64. Matching selected values does not qualify that whole native profile.
Before setup, fixture protected/hard/context evidence bytes were funded for
three product8MiB PCAPNG registrations, including existing format reserves:
29786112B rather than the pod-status seed's4632576B. Objects12/records3 and
all product limits stayed unchanged. Each case stored4592B synthetic PCAPNG;
accepted/grant input credit33554432B was reserved once each, never described as
measured observed input or CPU. Original source-expiry rollback, replay and exact
program/expectation checks remained effective.

Attempts1–4 remain overall failures: a retention version map keyed by display
name instead of UID; a last-row sponsor outside the author's actual group plus
stale shared permission state; an unconverted4KiB pod-status registration; and a
reused root/actor grant key across different policies. Narrow fixture fixes were
regressed locally. Attempt4's audience child passed, but its program child and
whole run failed. Attempt5 passed both children. Five attempts total111.132s
outer/47.682s Go; no deadline/quota increase or automatic retry was used.

The preserved session archive is
`codex-bf86-resume/policy-metadata-backing-5-artifacts` under the build cache.
`policy-metadata-backing-5-environment.json` SHA256
`d3017eefc52c969a10596972d7336e51c4d56c6caf17bc8555829fe0ae911f14`
and `terminal-verified-report.json` SHA256
`a590e99c0964fcb65296cbff0fb42ffe01579eaf82736938072ac8304b8e2610`
bind all3346 historical runner source hashes, actual exit0/unchanged=true,
cleanup[] and independently absent exact owned PostgreSQL/S3/OpenBao containers
and network. Archives1–4 remain intact. The source stayed clean after archiving
and restoring generated results. This documentation follow-up changes no tested
runtime/test source. Publication/native delivery, all64 native-profile records,
provider overhead/CPU, physical page growth/bloat/churn, backups/restore and
universal accepted-input backing remain unqualified by these two witnesses.

### Policy focus wire/parent-control correction after 3f native failure

Frozen3f Native40744737424 reached the corrected production CRD/activation, then
failed browser decide_review HTTP400. Its authored input incorrectly included
expected_revision, which the existing closed decide_review contract does not
permit. That field belongs to revoke_grant and remains required there. This is
a fixture input defect, not a failed reviewer/step-up/SQL effect qualification;
no production contract is widened. The original run remains failed: actual
Go444.452s, child6.73s, environment sourceUnchanged=true and cleanup[]. Its later
panic index2/len2 was a separate parent fixture fallthrough masking that error:
the post-region1 early-return list omitted policy-recording although its topology
is2. The inner journey closure return could not return its parent.

In a new isolated tree off3f, the actual native decision/revocation bodies are
shared with the offline canonical-contract test. Decision omits revision;
revocation preserves CAS, with negative tests enforcing both distinctions.
Browser fixture dispatch now validates the embedded input before HTTP as its
MCP dispatch already does. The parent return reuses existing
installedRecordingFocus() for all three recording focuses, rather than keeping
another incomplete string list. Other focuses stay unchanged; clusters is fast
but owns3 and still continues. No new selection framework, state, retry,
permission, deadline, capacity or authority behavior is introduced.

Actual decision-builder RED exit1/.063s and parent-controlflow selector RED
exit1/24tests are retained. Corrected affected Go races pass1.736s; selectors
24tests/.172s; integration vet0. The selector checks the actual parent segment
between region1 and region2 calls, not just the inner return; existing Go topology
table now binds recording-predicate membership including policy2 and clusters3.
All10 authored public operation names/12 body variants were separately audited
against exact embedded contracts: initial/attached activation, normal/1B policy
grant request, grant read, decision, CAS revoke, capture, case, policy status and
prepare/read download. Actual review builders are additionally covered directly
by Go tests; other MCP bodies already validate before dispatch. Audit is input
shape/format evidence, never authentication, effects or installed success.

Absolute cache logs: approved-workflow/policy102-focus-decision-input-red.log,
policy102-focus-parent-return-red.log, policy102-focus-wire-green.log,
policy102-focus-parent-return-green.log and policy102-focus-wire-vet.log.
Audit policy102-focus-all-authored-operations-audit.json SHA256
c22b655cb140ef22010c99089078a25d2b0ba31e21999892089a7f7c3f0d51ab.
No new hosted/owned fixture, collector or push was performed. Published3f and
main remain untouched; root reviews the frozen correction before any rerun.
