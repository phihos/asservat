# ADR-219 — Share acquisition for approved pod-status reads

Date: 2026-10-23. Status: implementation in progress; not yet qualified.
Requirements: REQ-MCP-002/004, REQ-AUT-002/005, REQ-EVD-005/008,
REQ-PRV-003/004; S-02; TASK-03/07/08.

## Problem and provenance

Approved content inspection through the console and MCP is a maintainer-required
capability. Native download is a separate capability. ADR-206 implements useful
authorization, query accounting and a fixed pod-status formatter, but has no
installed acquisition composition. Its proposed second worker identity,
enrollment and four-deployment capacity path are engineering choices, not
independent user requirements.

The maintainer has authorized implementing the specification while simplifying
unjustified machinery. Reuse the existing isolated acquisition lifecycle rather
than create a parallel one. This does not permit an approved query to impersonate
a download session or require download permission.

## Decision

Use a closed acquisition parent with exactly two purposes: an authenticated
native-download session and an approved pod-status query. The parent consists
only of its purpose and exact persisted ID. It is a locator, not an authority.
A common admitted worker identity binds that parent to the original worker ID,
installation, profile, Job, Pod, process key and lifetime. Unknown purposes,
mixed parents and substitution fail before provider or evidence work.

Keep `DownloadAuthority` and `ContextProjectionAuthority` distinct. Admission and
effects select their existing purpose-specific permission, retention, recovery,
processing, source and accounting checks. A common worker identity or acquisition
certificate grants neither kind of evidence access. In particular, `ReadApproved`
with `evidence:read` remains sufficient for this projection without
`evidence:download`.

Share the existing Restricted acquisition Job builder, product binary, namespace,
service account, protected configuration, issuer, enrollment/signing algorithm,
native-operation owner routing and outbound framed transport. Certificate
enrollment uses the admitted-worker identity contract of ADR-221 independently
of a human preparation socket. There is no new listener,
deployment, watcher, issuer, credential service or general query engine. Existing
native-download IDs, stored audit identities and behavior remain unchanged.
Historical migrations remain immutable; the forward schema change admits the
second closed parent without rewriting existing encrypted audit records.

The approved command has one fixed output: the independently verified
`asservat-pod-status/v1` DTO used by ADR-206's fourteen-line formatter. Its worker
reads only the exact admitted ciphertext/manifest/envelope/index version and
uses the query batch's own three one-use key roles. It has no byte-range/native
response command. The hub receives the bounded approved DTO, never an unwrap
key or the native source buffer. Offline arbitrary analyzers remain outside this
path and retain their separate isolation requirements.

Initial `get_file_excerpt` may admit one query and create its one exact worker.
`get_query_result` may read the existing worker's bound result under a fresh
request for the original principal/client. The worker independently finishes its
already-admitted enrollment under ADR-221, reusing acknowledged enrollment and
signing work within the original signing limits. A poll has no create,
replacement or enrollment-reset capability, and no human enrollment receiver
is registered for it. Unknown creation or
private completion stays charged; a later poll cannot turn uncertainty into
permission to repeat an effect.

Retain the existing query ledger, two charged read batches, exact source/display
selection, aggregate query budgets, output limits, outcome audit and positive
joined private closure. Count workers of both purposes against shared physical
worker limits as well as their purpose-specific accounting. Reuse the accepted
acquisition/hub/key/provider deployment and actual process limits; do not require
four additional dedicated deployments solely to qualify this small projection.
Sharing a process does not create free capacity: both parent types participate
in admission, and uncertain work remains counted until verified retirement.

The installed query backing is part of the existing protected capacity root and
workload enrollment. Its original setup reserves the additive query SQL,
backup/WAL, encrypted audit and key/provider allowance from that root's actual
residual. It does not invent a second worker, hub, key-service or provider
deployment, a measured report, or another source-observation claim/completion
loop. The old dedicated query-deployment format is unsupported for new work;
historical migrations and recorded component results remain historical.

The setup declares finite logical query costs before the acquisition profile
exists. Runtime plans bind those costs to the actual accepted acquisition
configuration and the exact enrolled target workload. Shared Job admission
counts both parent purposes against the existing physical limits; the existing
hub operation/native, enrollment and key-service slots also cover both purposes.
CPU, memory and the fixed ephemeral-storage Job limits are configured limits,
not measured peak use or a promise of spare scheduling capacity. History
footprints remain declared installer budgets until measured qualification.
No default or invented report digest may label them as measured results.

There is one root-wide charged query allowance. A target cluster is selected
only from its exact current enrolled workload and the accepted installed path;
adding a regional target does not clone the root allowance. The same protected
processing-location, client and purpose configuration applies to approved
metadata delivery through a purpose-specific policy view. This shares placement
configuration, never ordinary download permission or a `DownloadAuthority`.
`ReadApproved` and `evidence:read` still authorize the query independently.

The SQL-backed plan and private backing check are reusable by hub and key
service. They require the original setup/root, current source/workload,
accepted worker configuration and recovery fences; the key service needs no
human HTTP owner or extra capacity observer. Every current query effect keeps
its own SQL permission, processing, retention, recovery and charged-batch checks.
Original query/effect/cleanup/history dates and spent counters are immutable.

One complete authority observation belongs to its original public request.
Later helpers check that same observation, cancellation, exact scope and cutoff;
SQL effects retain their current permission, retention, recovery and processing
fences. A new poll authorizes again. No cache hit, pending reply, enrollment
completion or batch renews the query, source access, credential or request
lifetime. Installation and end-to-end qualification must measure the combined
cost, including cold Job startup and enrollment, before enabling the tools.

## Lifetime and physical cleanup

The installed shared profile explicitly selects a 60-second query/worker
lifetime, bounded by original access, retention and accepted backing. This
replaces the older ten-second default for this installed composition; it is a
finite engineering choice, not a measured cold-start guarantee. Each public
invocation and current effect retains its original bound. Four paid status
polls and two paid read batches remain unchanged. Pending replies carry the
original query deadline and a not-before interval; callers must not spend all
polls immediately while waiting for cold startup.

Abandoned query cleanup uses the existing admission/status demand, including
native-download admission. Each demand reads at most sixteen expired workers
and attempts at most one, rotating selection so one uncertain Job cannot
monopolize the bounded list. There is no new timer loop, watcher or service.
The original caller owns and bounds that work; cleanup grants no evidence
access and does not need the admitting human to return.

An expired worker whose locked row proves no create claim was ever issued may
be marked irreversibly abandoned. Claimed work remains charged until the exact
Job and sole Pod are observed terminated, that identity/termination is persisted,
foreground deletion uses the original UID, and independent absence is proved.
An absent Job, unknown create, changed profile, extra Pod or failed cleanup does
not refund capacity. These transitions release only the physical worker slot;
the original query/history/audit/key charges and retirement horizon remain.

The new installed qualifier adds at most six ordinary audited operations: one
native-download denial with a real read-only OAuth session, one initial approved
request and four polls. It does not increase the fixture's existing normal-64 or
resolution-2 allowances. It checks original query/worker identity, actual key
consumption and joined batch closure, and compares the approved fourteen fields
to the subsequent native file. The native download, revocation, expiry and
deletion assertions remain required. These checks are authored, not yet run.

## Complexity assessment

1. **Frequency/harm:** installed approved content is entirely unavailable, not a
   measured rare failure; this blocks the requested inspection workflow.
2. **Accepted risk:** bounded permission observation is accepted. Do not add
   instantaneous distributed-revocation claims or repeated full helper checks.
3. **Typical use:** reading already captured pod status is a basic workflow.
4. **Precedent:** the repository's existing acquisition lifecycle is the concrete
   reuse baseline. No external industry comparison is claimed.
5. **Added exposure:** zero new deployments, listeners, issuers or watches. The
   existing isolated worker gains one purpose-scoped approved command. SQL/key
   grants gain only the exact query operations; the hub gains no unwrap right.
6. **States:** reuse admitted, pending, active, uncertain and retired worker
   states. The two parent purposes are a closed discriminator, not parallel
   lifecycle state machines or fallback modes.
7. **Configuration:** no switch to tune this reuse. Retain explicit accepted
   processing locations and finite operator budgets.
8. **Dependencies:** existing Kubernetes, PostgreSQL, object store and key
   provider only; their latency and failure modes still require qualification.
9. **Aggregate cost:** at most one Job and two source-read batches per query;
   at most three key consumes per batch; 4096-byte source, 24-KiB structured and
   64-KiB wire ceilings. Existing certificate attempts are not multiplied by a
   second enrollment protocol. Actual API counts, latency and peak memory remain
   unmeasured for the complete installed projection and will be recorded.
10. **Change/disable:** forward schema preserves existing native IDs and audit
    history. The candidate requires SQL and installed qualification before user
    deployment; disabling new admission does not erase existing charges or
    bypass cleanup.
11. **Smaller alternative:** reuse the fixed formatter and existing worker. A
    download prerequisite would change permissions; hub decryption would change
    isolation; metadata-only case descriptors do not satisfy approved content.

## Qualification and limits

Tests must exercise read-without-download success, rejection of cross-purpose
commands/keys/parents, exact admitted-worker enrollment across pending calls,
unchanged native download behavior, current SQL fences after blocking locks,
mixed-purpose capacity and conservative uncertainty, cancellation/joined remote
closure, and equal browser/MCP results. The installed journey must cover the
complete acquisition-to-audited-disclosure path at production resource limits.

This decision is the implementation contract, not evidence that those checks or
the installed workflow have passed. Track commands, actual exits and remaining
composition in the implementation-progress record.

## Revision 2026-10-23: reads without workload capacity

Maintainer decision (explicit, 2026-10-23): reading already stored evidence
must not depend on live capacity observations of the source workload.
Migration 00076 (schema 76) removes the workload and root capacity
observation from approved-query reads. `lock_context_query_capacity` checks
only the immutable accepted anchor (installation incarnation, recovery issuer
epoch, original `HardUntil`); `context_query_capacity_allocation_current`
checks only the workload's immutable reserved allocation against the backing;
`read_shared_context_query_plan` no longer consults
`capacity_managed_root_until`. The workload's `context_storage_binding`
freshness, `capacity_workload` revision/pool/policy match and capacity source
suspension no longer gate query admission, worker batches or polls. Reads stay
bounded by the shared acquisition worker limit, the original root, principal
and per-workload query charges, per-principal operation-audit allowances, and
every permission, retention, recovery, processing, catalog and accepted worker
configuration check. Evidence of a deleted workload stays queryable within
retention. Capture admission is unchanged.
