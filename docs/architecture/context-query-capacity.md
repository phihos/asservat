# Protected context-query capacity

This is the original-install-only C-07 backing for
[ADR-206](../decisions/206-bounded-context-projection.md). It supplies private
compiler, producer, reader and C-03 environment components. It does not provide
an installed resource qualification, a runtime role grant or public tool
registration. An installation that omitted the extension remains unavailable;
adding it to an existing installed root needs a separate audited revision
protocol. No rolling allocation epoch or automatic replenishment is implied.

## Original acceptance and independent proof

`CapacityQualification.ContextQuery` is an optional closed extension of the
original protected setup input. Omission preserves the old serialized bytes.
When present, the full profile, policy, report identity and source tree, exact
profile digest, history layout, deployment identities and numeric limits are
bound by the existing immutable setup receipt. C-07 independently requires the
original root attempt and plan, installation, current accepted capacity source,
phase-three root readiness, encrypted permission acknowledgement and current
recovery/database incarnation. It cannot adopt a synthetic query-backing row.

The report reference is not itself measured evidence. Four mandatory independent
`QueryDeploymentGuard` instances must bind that original protected acceptance to
the accepted measured report and the actual worker, hub, key-service and provider
deployments. Each is installation/root-bound at protected construction, checks
its exact image/configuration/protection identities and enforced limits, and
rejects known source changes, suspension, lost continuity or recovery changes.
A caller-supplied struct, administrator declaration, report digest, bare UUID or
worker-only proof cannot replace these checks. Native Pod resource checks prove
only their actual enforced dimensions; executable read, authentication, provider,
copy and control limits need their own exact-image qualification.

Each deployment records explicit CPU, memory, ephemeral storage, transient-copy
and concurrency limits. Their exact sum is the dedicated combined reservation.
The worker must independently cover all root query slots' worker requirements;
the hub covers hub copies, the provider covers provider concurrency, and each
role's authentication concurrency is separately bounded. A large hub cannot
compensate for an undersized worker. This layout requires distinct physical
cluster/namespace/workload identities for those deployments; four role names
cannot multiply one deployment limit. Shared physical processes require a
separately accepted partition contract before they are supported. `CapacityID`
prevents reusing the same
reservation identity; independent protected native acceptance must also prove
that the actual capacity is exclusively assigned and not pledged under another
identifier or installation. No download profile or default twenty-minute
credential interval supplies query capacity.

## Finite arithmetic and original horizons

The original base root graph retains its exact totals. Migration69 reserves a
separate immutable additive charge from the original root envelope minus those
totals, including SQL, backup, WAL, audit ciphertext bytes/objects and key/provider
requests. It also checks the real system-pool residual. The extension neither
inflates existing `backed_system_*` counters nor takes a second copy of a base
reservation. The dedicated process envelope is independently measured and
reserved in full, including uncertainty after query expiry.

A fixed root query limit covers all queries across principals and clients. The
principal key excludes OAuth client ID; changing clients cannot obtain another
principal budget. Each exact protected workload allocation reserves its entire
query slice before any query starts. Workload-account count times its slice
cannot exceed the root. A new workload name, poll, timeout or lost reply does not
reclaim an old allocation. The existing immutable workload revision, pool source
and policy source remain current prerequisites.

Every query prepays its bounded invocations, control transitions, provider and
authentication requests, one worker, two read batches, six unwrap attempts,
output/copy ceilings, encrypted audits and SQL/index/backup/WAL history. Poll and
control ceilings are independent; two result batches do not mean two polls.
The accepted report must cover the exact composed executable and SQL layout,
including credential continuation and durable first-Pod observation work. The
closed `context-query-worker-history/v1` layout requires at least
`8 + SigningAttempts` fixed query rows, one row per initial/poll invocation and
one row per prepaid control transition. The total is
`FixedQueryRows + (1 + PollLimit) * InvocationRows + ControlTransitionLimit * ControlRows`.
These conservative schema counts do not measure row/index bytes or WAL. The old
`context-query-history/v1` declaration and SQL68's `8 + PollLimit` floor cannot
qualify this worker composition. Encrypted object slots include
`2 * (1 + PollLimit) + 1 + SigningAttempts`: each invocation's intent/outcome,
one immutable enrollment object and at most one certificate object per signing
attempt. These child audits also need their actual qualified key/provider work.
The source
producer also has a finite observation allowance, with its authentication,
provider and WAL work prepaid separately. One terminal negative transition is
reserved after positive observations are exhausted. Unknown or failed work never
replenishes these allowances.

The query-backing hard cutoff derives from the root's original observation plus
its accepted admission duration. Compatible base-root renewal cannot move it.
The effect cutoff adds the greatest original worker, credential or provider
obligation; cleanup adds the independently accepted worker cleanup allowance.
History retirement retains cleanup plus two qualified backup horizons and the
retirement-cleanup bound. These dates remain distinct from the per-query total
lifetime and each invocation's original at-most-five-second current authority.
There is no refund, retirement implementation or proof of remote closure from
elapsed time alone.

## Locks, current checks and environment

Positive SQL uses recovery, permission, capacity source, immutable query anchor,
query backing, allocation, principal/query/batch/key lock order. The query ledger
must call `LockContextQueryCapacity(root, acceptance)` after permission and
`ContextQueryCapacityAllocationCurrent(root, allocation)` at its final fences.
`ContextQueries.current` calls the mandatory source/anchor lock after recovery
and permission and before query backing/allocation locks. Its fence checks the
exact current protected workload allocation after blocking reads, both before
and after each effect, then rechecks original bounds using database time. A
successful external callback cannot substitute for a missing or changed SQL
anchor. Passive lookup and restrictive historical batch closure grant no new
effect authority and retain their separate original bounds.

External guards surround the SQL callback and run outside SQL locks. Parent
cancellation and every earlier guard deadline survive context replacement.
Omitted/repeated/late callbacks cannot report success, and final checks cannot
turn a late completed callback into a current permit. SQL checks database time
after locks and compares the exact original installed plan. Read facets cannot
accept, suspend or allocate capacity. The producer's separate restrictive
suspension operation records a monotonic negative without refunding capacity;
a current positive observation can clear it only within the original finite
allowance and after all independent guards succeed.

`ProtectedContextQueryCapacity` supplies the accepted policy to C-03's
`CurrentProjectionEnvironment`. That environment independently checks current
client/purpose/region policy, recovery and complete durable processing state,
then repeats each check before returning. It consumes the existing purpose-
neutral processing read through `ContextProjectionProcessing`; it does not
require download permission or convert a download policy into query authority.
The original backing freshness can shorten the returned policy even when the
parent source is newer. No blocking read or later observation renews an earlier
cutoff. Current ordinary `ReadApproved`, complete denies, retained audiences and
retention remain the separate C-03 authorizer's responsibility.

## Validation and remaining composition

Unit/race tests exercise independent residual dimensions, measured-profile
identity, per-role resource isolation, immutable original dates and input
ownership, all four mandatory guards, callback/cancellation/deadline failures,
current source changes and the C-03 environment. The selected real PostgreSQL
fixture uses actual original setup receipts, scoped roles, permission audit,
phase-three root and workload activation. Its query reports and native guards
are explicitly synthetic; the run status is recorded in implementation progress.

Production measured report acceptance, all four protected native guard
compositions, installer-selected query configuration and narrow role provisioning,
query worker/key delivery, sustained installed
qualification and bounded retirement remain separate requirements. Missing
qualification stays unavailable. Neither Helm nor browser/MCP availability
changes here.

The owned `TestContextQueryCapacityWithRealPostgres` selection passed at
`896e491a3e7ceb610a3ce3a4fb228c9f34628933`, including actual original installation,
capacity root/workload setup, positive/replay/negative reservation and scoped
consumer-fence calls. All 2,642 source hashes matched the frozen commit and
cleanup completed; the [environment report](../../test/results/context-query-capacity-native-environment.json)
and [run log](../../test/results/context-query-capacity-native-run.log) retain the
exact selection. The first run exposed an ambiguous PL/pgSQL digest-index alias;
its correction changes no limit or authority rule. Query resource measurements,
history measurements and independent native deployment guards remain synthetic
in this component fixture. The full SQL68 ledger workflow, real accepted
resource proof and installed query composition require their own qualification.
