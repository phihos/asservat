# ADR-311 — Run browser-session cleanup in the existing worker

Date: 2026-11-05. Status: implemented; local real-role qualification passed, installed caller qualification pending.
Related: [ADR-060](060-bounded-browser-sessions.md),
[ADR-061](061-current-browser-configuration.md),
[ADR-210](210-installed-processing-changes.md),
[ADR-222](222-hub-process-sql-credentials.md).

## Observed gap

`BrowserSessions.Cleanup` and its bounded SQL statements existed, but the
installed runtime never called them. ADR-222 retired an unused cleanup
credential rather than provisioning it. Expired authentication already refuses;
the gap is physical retention of encrypted login/session credentials and logout
metadata without foreground traffic. Local/provider logout already deletes its
selected sessions immediately. Cleanup is not a new revocation protocol.

The compiled browser-settings role also lacked the metadata reads and candidate
row locks needed by pruning. An actual compiled-profile regression first failed
on `browser_login.id`; this is local component evidence, not an installed test.

The first actual worker-role campaign then exposed a separate existing SQL
bound defect: one pass removed 299 of 304 sessions rather than at most 256. An
isolated PostgreSQL EXPLAIN ANALYZE reproduced a nested-loop semi join that
rescanned the limited candidate subquery 304 times. All three prune statements
now materialize their candidate IDs exactly once before DELETE. Their expiry,
epoch, refresh-claim and SKIP LOCKED predicates and 256-row limits stay unchanged;
there is no new table, role or migration. The actual-service regression checks
both the first bounded pass and the remainder on the next independent pass.

## Decision

Reuse the installed permission worker's browser-settings child, its existing
loop and its one-connection SQL pool. After reconciling settings, prune once at
startup and at most once every 60 seconds. A source outage, stale observation or
suspension does not skip pruning. Cancellation of the owning Lease stops it, and
the existing joined-child shutdown waits for an in-flight attempt. A cleanup
failure is reported through the existing closed error-category logger and is
retried on the next 60-second pass; it does not enable settings or revive a
session. No provider error text or credential is logged.

Each attempt has a one-second operation deadline, narrowed by the original
owning context. The existing SQL transaction can additionally join rollback
for up to one second; no effect is authorized after the operation deadline.
This bounds interference with settings reconciliation on the same connection.
The cadence and bound are engineering choices, not authority lifetimes or new
operator configuration. The usual SQL transaction/lock bounds remain in force.

The settings projection locks the exact configured session root and takes its
current stored epoch under that lock. It then invokes the existing three prune
statements without changing their predicates: expired/retired-epoch login and
session state, sessions with an expired one-use refresh claim, and expired or
retired-epoch logout receipts. The original bound-epoch `BrowserSessions.Cleanup`
continues refusing an old instance after epoch rotation. Housekeeping requires
no fresh enabled-settings observation because it cannot authenticate, renew or
read provider credentials.

Keep 256 rows per table per pass, the existing root-before-session lock order,
`SKIP LOCKED`, fixed session expiry, one-use refresh and 25-hour logout receipt
cutoffs. Preserve unexpired current-epoch receipts, active refresh claims,
current live credentials and other session roots. No table, column, schema
migration, new SQL role, credential, KMS access or public endpoint is added.

The existing browser-settings role gains exactly 11 ACL entries: SELECT on three
additional login metadata columns; UPDATE(id) for login candidate row locks;
SELECT(claim_until) for sessions; four logout metadata SELECT columns;
UPDATE(id) for logout candidate locks; and logout DELETE. Existing settings
administration privileges are unchanged. It gains no ciphertext/provider identity
read, INSERT or ciphertext UPDATE. The public ingress role remains separate.
The compiled role-layout digest changes; original role receipts/ACL verification
must match the new profile. This does not adopt or silently broaden an old
installation credential.

## Cost and retention bounds

One pass performs one root lock plus three bounded deletes, within one existing
transaction (BEGIN, local timeout setup and COMMIT). There are no extra Kubernetes
requests, watches, goroutines, connections, services, dependencies or timers.
Steady-state housekeeping adds four statements per 60 seconds per elected worker
(0.067 statements/second), plus that transaction's existing setup/commit.

At most 768 rows are removed per pass: 256 per table, or 4.27 rows/second/table
under a sustained backlog. This is eventual physical cleanup: a normal eligible
row waits up to the next successful60-second pass, plus one pass for each 256
older eligible rows ahead of it. For 100,000 simultaneously expired sessions,
391 successful passes take about 6.52 hours. Actual SQL outages, worker downtime,
locked rows or one-second attempt exhaustion can delay removal further; they do
not extend authentication or logout authority. No hard deletion SLA is claimed.
Application row deletion does not erase PostgreSQL backups/WAL; their separately
accepted retention and restore-epoch requirements remain open.

Compared with the existing one-second component cleanup loop, the installed
cadence reduces idle housekeeping by 60×. Doing nothing or documenting the gap
cannot remove rows. A separate cleanup service, role or periodic framework adds
cost without changing the expiry decision, so none is introduced.

## Validation boundary

Focused tests cover the actual compiled ACL profile, cleanup during settings
failure/suspension, bounded retries and joined cancellation. The managed service test on signed `f8c4a86a` uses the actual compiled worker
role and SQL adapter and passes (Go/harness exit 0, 4.698 s, 2 selected tests), including
300-row backlogs, exact256/remaining passes, live/old-epoch state, original
receipts, ACL denials, logout and blocked-lock cancellation while settings are
unavailable. The first 768-row pass takes 19.902282 ms for small synthetic opaque
records; maximum credential sizes and sustained ceilings are not measured.
All 4,303 source hashes match exact Git, source remains unchanged and cleanup
is complete. Its payload/identity/source setup is synthetic; this does not
qualify the installed worker scheduler or a real identity provider.
[Original reports and failure history](../../test/results/browser-session-cleanup-local/README.md)
retain the actual boundaries.

## Focused installed caller proof prepared

The existing node-free `continuation-browser` focus now invokes one helper only
after its foreground journey has returned and joined its clients. This matters:
login/session creation also prunes, so overlapping HTTP activity would not prove
the background worker called cleanup. Other installed suites gain no wait.

The helper pins the exact installed browser ConfigMap and its SQL root, seeds
three expired and three live synthetic opaque control rows under the original
ceilings, then makes only SQL reads while waiting within the original caller
and a 75-second proof bound. It calls neither the cleanup adapter nor HTTP nor
administrator DELETE during observation. Stable epoch/binding/limits/source
identity stay fixed; normal observer timestamps may advance. Only after expiry
is observed are the exact synthetic IDs retired by the fixture. No real
provider token, product session or authority is supplied by the seed.

Live controls retain NULL claim fields. Actual refresh claims last ten seconds;
no artificial long refresh claim is introduced to outlast the minute cadence.
Unexpired active-claim preservation remains the separate real-role component
control, not an installed refresh-concurrency claim.

Incremental cost in this one focus is one ConfigMap GET, a small seed transaction,
at most 39 poll iterations/two SQL reads each, and three exact-ID control deletes.
The existing twenty-minute job/caller bound is unchanged. Local helper races and
compilation are not execution of that installed proof; actual qualification is
pending Root's integrated candidate and authorized campaign.
