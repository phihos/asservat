# Grouped Save dispatch within original authority

Status: engineering decision; implementation and local controlled checks in
progress. Installed and sixteen-source native qualification remain pending.

[REQ-SAV-002](../../specs/recording-saves.md) requires one atomic admission and
independent child outcomes afterward. It does not require every sibling's
capture intent to be acknowledged before any child starts. Each child still
requires its own exact durable acknowledged intent and current policy and
initiator authority before its effect. A failed sibling cannot authorize work
or suppress otherwise valid admitted children.

The previous coordinator spent the request interval writing optional encrypted
history, then acknowledged all child intents sequentially before starting any
child. Central sixteen-source qualification had 732 ms of the original
admission proof remaining; a separate actual encrypted parent-history sample
cost 2.75 seconds. Those component samples show a composition problem, not a
production latency percentile or a native capture measurement.

Use at most sixteen joined acknowledgement calls, with one bounded result per
admitted child. The original request owner validates each ready result and
performs current identity checks and starts serially. This preserves the
reference Router's one capture conversation; it does not increase its capacity.
Only the owner narrows contexts. Cancellation cancels and joins every audit
worker; no detached dispatch queue, retry or additional lifecycle state is
introduced. One bad intent produces a child failure while siblings can proceed.

Move the optional single history attempt after start attempts. It uses only the
remaining original request interval and cannot undo admission or start. Read
fresh response metadata for the same parent and every exact immutable child
when the initial observation expired. This is an accepted-only lookup, never
another admission, audit write, start or new t0. Passive replay stays passive.

Select a prospective fifteen-second `request_capture` invocation window at
browser/MCP ingress through the existing request-owned identity `Within`
constructors (existing maximum twenty seconds). The same operation names both
first Request and explicit Continue. Protected grouped admission uses the
longer composition window; singleton execution retains its original five-second
application bound. Other operation windows remain unchanged. Because the group
is known only after reading its protected preview/accepted row, the shared
`request_capture` transport/audit envelope permits fifteen seconds; this does
not authorize a finite singleton to start later. Initial authentication remains
bounded to five seconds.

Five-second whole-invocation composition was an agent-authored engineering
choice. Changing it prospectively never widens an existing caller context,
identity observation, token or browser session. A shorter initial or later
identity validity still wins permanently. Admission/current-facts checks keep
their original five-second phase; every accepted snapshot retains its immutable
SQL t0 and StartBy=t0+5s. The dispatcher explicitly caps each audit/start by that
original StartBy. Current phase proofs must be obtained and consumed within
their own intervals; an old response-metadata or recovery read does not become
a renewed acquisition permit. No source, grant, policy or write end is extended.

Migration111 replaces the existing operation-audit guard with one additional
`request_capture` fifteen-second case. Evidence reads retain twenty seconds,
all other names five seconds, and write/audit-account/retirement/receipt guards
are unchanged. Down first refuses while any retained `request_capture` intent
has more than five seconds, including expired records still needing audit
retirement. A migration-only shared table lock serializes that check with
writers. Compatible five-second rows and residual aggregate history do not
block downgrade. Otherwise Down restores the previous exact guard for future
effects; immutable existing operation intervals are not rewritten. There are no new
schema tables, roles, query ports, collector permissions or keys.

## Complexity assessment

1. Observed composition: optional2.75s history cannot fit within732ms remaining;
   full sixteen-source dispatch was not covered by the central SQL component.
2. Preserve accepted original intervals, current rights and independent outcomes;
   remove the unnecessary all-sibling barrier, not per-child audit.
3. Benefits ordinary multi-replica saves; singleton application timing unchanged.
4. Reuse existing request identity, child start, Router and custody mechanisms.
5. Zero additional roles, credentials, endpoints, collector privileges or tokens.
6. Zero new durable lifecycle/degraded/fallback states; existing child outcomes.
7. Zero user configuration; one fixed operation-specific fifteen-second window.
8. Zero dependencies/services; existing provider and Router capacity remain binding.
9. At most16 joined audit calls/results; total existing audit/start work unchanged,
   but concurrent audit burst can reach16. Starts remain serial. Request residency
   can reach3x the former5s envelope, within existing admission slots. No watches,
   observers, retries or new Kube API reads. Measure complete1/2/16 workflows.
10. Existing accepted dates do not change on upgrade/rollback. Test exact guard
    restoration, current identity shortening, joined cancellation and passive replay.
11. History ordering alone, concurrency alone, or a local timeout change alone
    cannot repair the composed request. This bounded reuse fixes all three;
    real Router timing and native qualification are still required before enabling.

Controlled application timing replays use actual RecordingSaves,
ContextInvestigation, ContextSubmission and a real request-owned bearer handle;
SQL/audit/start/history effect ports are explicitly synthetic. Positive controls
spend3.2s in simulated SQL after t0, then16 serial100ms starts. A negative
control spends3.410s in SQL and300ms per start: remaining children refuse under
the unchanged StartBy instead of receiving a fresh five seconds. These costs
and2.75s history are controlled parameters, not typical regional latency. The actual RegionalStart/Router test must retain Standby2/Captures1.
A passing control test is not sixteen native artifacts or installed qualification.
