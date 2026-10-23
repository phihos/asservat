# Shared installed context-query capacity

[ADR-219](../decisions/219-shared-approved-acquisition.md) replaces the unshipped
four-deployment query capacity producer. Approved pod-status queries use the
existing installed acquisition worker, hub, key service and providers. They keep
separate `ReadApproved` authority, immutable query state and charged work. No
second source observer, query deployment, physical partition, role or credential
is introduced by this capacity composition.

## Original acceptance and exact workload

`CapacityQualification.ContextQuery` is a closed original setup extension with
format `shared-installed-context-query/v1`. An installation without this extension
cannot create query backing; earlier dedicated layouts are rejected for new work.
The installer declares logical work/history costs before worker configuration
exists. Its root profile therefore contains no selected target cluster or worker
configuration. Each plan combines that immutable budget with the actual protected
placement for the exact allocated workload and current accepted acquisition
configuration. Multiple clusters share one root limit; a cluster does not obtain
a copy of that allowance.

The existing root publication transaction accepts one immutable residual query
reservation. Existing successful workload publication and refresh transactions
ensure the same exact query allocation. Unknown replies retain the original
anchor/allocation IDs, charges and dates. They cannot create a new reservation.
No administrator inserts those rows in the qualification fixture. The same
original setup receipt, current capacity source, phase-three root readiness,
permission acknowledgement and recovery/database incarnation remain mandatory.

## Logical accounting and shared physical admission

The original base root totals remain exact. Migration71 independently checks the
query reservation against original SQL, backup, WAL, audit-object and key/provider
residual budgets and the actual system-pool envelope. It adds no capacity or
refund. Each principal has one finite account across OAuth clients. Exact workload
allocations reserve their full slice, and their sum cannot exceed the root.
Replacement workload identities, timeout, query expiry and restart do not reclaim
old history or replenish allowances.

The installed declaration uses a 60-second query lifetime, four paid status polls,
32 control transitions, one worker and two charged read batches. Each batch is
bounded to the existing 4-MiB read-work, 24-KiB structured result and 64-KiB wire
ceilings; six unwrap attempts cover two sets of three keys. The source artifact
itself remains the 4096-byte pod-status profile. These are configured ceilings,
not measured overhead. Worker CPU/memory and 4-MiB ephemeral storage match the
actual shared Job profile. Both parent purposes consume the same physical worker
admission limits and hub/key/provider concurrency; logical lifetime counts do not
multiply those resources or promise spare scheduling capacity.

The `shared-context-query-history/v1` layout includes at least
`8 + SigningAttempts` fixed rows, `(1 + PollLimit) * InvocationRows`, and
`ControlTransitionLimit * ControlRows`. Encrypted audits require
`2 * (1 + PollLimit) + 2 + SigningAttempts`: invocation intent/outcome, separate
worker-intent and enrollment objects, and certificate objects. The installer
uses existing operator-declared row/WAL estimates to derive the finite reservation.
The WAL estimate also includes nine shared worker/enrollment transitions and four
per certificate attempt, which do not increment the query control counter. These
sizes are configured estimates, not measured upper bounds. There is no additional
query source-transition claim or its three-transaction observation history.

The hard admission cutoff derives from the original root start plus its accepted
admission duration. Worker, credential/provider, cleanup and history-retirement
obligations remain separate, original finite dates. Root renewal, polling and
source observation never move those dates. A returned query result does not prove
remote retirement; physical worker release requires the existing terminal proof.

## Current checks and composition

`SharedContextQueryPlans` reads the exact installed root/allocation and matches the
accepted worker profile. Its backing wrapper makes only local scope, cancellation
and original-deadline checks around the callback. It never reacquires a SQL pool
or performs provider work inside an effect transaction. The same constructor can
serve the hub planner and A-KEY backing guard without a second capacity producer
or human HTTP owner.

The ledger still locks recovery, permission, capacity source/anchor, query backing
and exact allocation. Before and after effects it checks current permission,
retention, processing, published source, accepted worker configuration and workload
allocation under SQL locks, and checks database time against the unchanged
caller/authority/query limits. Callback success cannot replace these checks.
Historical backing observation dates do not become a second heartbeat deadline:
currentness comes from the existing accepted capacity source and configuration.

`ContextProjectionPolicies` selects the exact target/store path from the existing
raw protected installation policy. It preserves original policy dates and returns
a distinct approved-projection policy; it never consumes a `DownloadAuthority`
or grants evidence-download permission. The C-03 authorizer still independently
requires ordinary `ReadApproved`, complete denies, retained audience, retention,
recovery and processing checks. Direct administration remains at its existing
five-second policy interval.

## Qualification

The current shared implementation and adapted SQL fixture require their own
recorded checks; historical component passes below do not qualify this composition.
The selected SQL tests retain actual original setup/root/workload publication,
immutable charge replay, closed-shape/residual negatives, current configuration
refusal after a lock wait, uncertain query admission and finite spend. Protected
Kubernetes observations, human identity and C-14 worker ownership remain explicit
fixture inputs. Full installed UI/MCP query delivery remains a separate gate.

## Historical dedicated-producer results

The following reports qualify their exact earlier source, including the now
removed observation mechanism. They are retained as history and make no claim
about the shared installed path above.

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
