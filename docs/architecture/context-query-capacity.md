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
The source producer also has a finite observation allowance. Before entering
any of the four native guards, an acknowledged committed Begin consumes one
original ordinal and pins its exact original interval. Unknown or replayed
Begins permit no native work. The bounded latest claim is held across acceptance,
all outer guard checks and final source reads; only a separate restrictive
joined completion allows another attempt. A synchronous failed guard may record
that joined completion under the original prepaid cutoff, without accepting a
source. Expiry never proves that unknown work joined. Missing stored completion remains held; this component has no recovery bypass.
If the completion commit succeeds but its reply is lost, that invocation still
fails, while the durable joined record can support a later fresh paid attempt.
An uncertain Begin has no corresponding joined record and never grants work.

Three complete SQL transactions per source attempt (Begin, acceptance and joined
completion) are included in the WAL floor, alongside the separately prepaid
native authentication/provider work. Failed or unknown work never refunds these
allowances. The first Begin reserves the original additive root charge; its
anchor alone cannot supply positive backing. One terminal negative transition
remains reserved even when the source never reached positive acceptance. A
negative invalidates older acceptance claims without releasing unresolved work.
Current source observation never creates a rolling interval or replenishes the
original installation budget.

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
turn a late completed callback into a current permit. A plan newly shorter than
the already combined caller/authority/source/guard bound is rejected before
effects or an outer source read. Final source or plan observations that shorten
that used bound also reject the operation, so outer guard completion cannot
report success after the new cutoff. An earlier caller bound remains usable:
comparison is against that effective bound, not an unbounded source lifetime.
Prepared effects are never rewritten or repeated to recover from such denial.
SQL checks database time
after locks and compares the exact original installed plan. Read facets cannot
accept, suspend or allocate capacity. The producer's separate restrictive
suspension operation records a monotonic negative without refunding capacity;
a current positive observation can clear it only within the original finite
allowance and after all independent guards succeed.
Delayed negatives retain their original observation time even after its
five-second interval has expired. Their restrictive SQL write gets at most five
seconds from the current call, further bounded by the caller's original deadline
and cancellation. This does not create a fresh source interval: SQL retains the
old watermark and expired freshness, and older negative replays change neither.

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

The separate `TestContextQueryLedgerWithRealPostgres` selection starts with its
own pristine installation and uses that producer for the full SQL68 ledger
regression. Managed capture admission and independent publication provide the
source artifact; current query policy, processing, retention and ordinary rights
provide C-03 authority. The original setup reserves the complete normal audit
pool and finite source observations. No administrator inserts a query anchor,
backing or workload allocation. The synchronized negative case only suspends
backing; a fresh protected producer observation must restore it. Worker/closure
proofs and measured native capacity remain explicit synthetic inputs. This
selection runs separately from other pristine-installation cases, and closes
its helper pools before the fixture ends.

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
in this component fixture. The subsequent assembled selection at
`446eeb5e9ccb083b1919dee4f0cdd835df7e31e5` independently qualifies this producer
and the full SQL68 ledger in separate fresh owned fixtures. Both reports match
all 2,651 source hashes and record exit zero with complete cleanup:
[capacity](../../test/results/context-query-capacity-assembled-1/fleet-environment.json)
and [ledger](../../test/results/context-query-ledger-assembled-1/fleet-environment.json).
Real accepted resource proof and installed query composition remain separate.

The source pre-I/O accounting correction is later than those historical reports.
Fresh separate native capacity and full ledger selections passed at
`51fd2e94d41d6ce5e9105b755e7e39671df5944e`, each with all 2,652 source hashes matched,
unchanged source and complete cleanup. The [capacity report](../../test/results/context-query-source-spend-capacity-1/fleet-environment.json)
and [ledger report](../../test/results/context-query-source-spend-ledger-1/fleet-environment.json)
qualify the new SQL claim/completion protocol, including failed/unknown starts,
concurrent work, expiry without completion, exhaustion and negative fencing.
Synthetic resource measurements and guard/authority inputs retain the limits above.

The delayed-negative adapter regression first failed at `f8d73a8`, then passed
at `e538a403`. The final assembled capacity selection passed at
`7fcc30fd0bd4d1896cbe843d555f37b2b211767c`, matching all 2,652 source hashes with
unchanged source and complete cleanup. Its
[report](../../test/results/context-query-stale-negative-assembled-1/fleet-environment.json)
and [log](../../test/results/context-query-stale-negative-assembled-1/fleet.log)
cover persistence after the original negative is over five seconds old, no
freshness renewal from an older replay, and the caller's earlier deadline while
blocked on SQL locks. The full ledger result remains scoped to `51fd2e9`; it was
not rerun for this restrictive adapter-only change. Installed/public query
qualification remains pending.
