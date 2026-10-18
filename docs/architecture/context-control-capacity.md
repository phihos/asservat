# Context control capacity

[ADR-108](../decisions/108-backed-context-control-capacity.md) and migration37
replace the global historical 1,024-capture admission check with protected
workload allocations. This is capacity isolation, not complete metadata cleanup.
U13 remains open until finite dependency-aware retirement is implemented and
qualified. Evidence storage bytes and objects keep their existing C07 accounts.

`context_control_pool` is root-wide because all evidence stores share the hub's
SQL control budget. `context_control_account` is bound to the existing immutable
`context_storage_binding` and custody allocation. Each account's entire
full-record/replay-record limit is reserved at the pool before use; there is no
borrowing. `context_control_charge` maps each accepted capture to exactly one
account. Both slot counters advance once, in the capture admission transaction.
The deferred database constraint prevents an accepted capture with no charge.

The C07 `ContextControlBacking` facet takes protected configuration, with no
public wire change. Pool and account updates require the exact previous
revision and advance one revision. Initial configuration also adopts legacy unconfigured costs without
resetting them. Renewal changes the same identities; exact old replay cannot
re-extend expiry or overwrite a newer revision. Safe shrink changes only unused
backing, never charged metadata or evidence. Pool/account pause independently
stops new admission. Every mutation retains its original at-most-five-second
configuration observation through SQL waits. The application uses root
serialization and custody pool/allocation lock order; no provider or identity API runs inside SQL locks. New admission
rechecks the earlier control expiry after all blocking work and before COMMIT.
The SDK/browser response retains its separate original metadata authority bound.

The configuration credential cannot acquire evidence, insert charges or reset
counters. The capture credential can read/lock configured accounts and insert
an exact charge, but cannot change limits, counter columns or delete records.
Narrow trigger functions have a fixed `pg_catalog,pg_temp` search path, qualified
relations, exact trigger source checks and no public EXECUTE. They perform only
the source-defined backing/charge increment; they do not authorize acquisition.

Migration adoption counts every historical row without parsing labels into
terminal proof. It preserves all original IDs, custody references and accepted
bytes. Existing costs become reserved backing even when the pool is initially
unconfigured. Configuration that cannot cover those costs fails; original
accepted replay remains possible with its existing current identity/rights checks.
No cascade or record removal occurs.

The existing `ContextStorageReader` includes the selected account/pool in its
single MVCC observation and reports capacity failure before creating a review
when a dimension is exhausted. The source's original freshness is shortened by
control expiry, never renewed. The observation reserves nothing; another request
can still win the last slot before submission.

`ContextRetirementReads` is a separate C15 SELECT-only diagnostic. It reports
custody deletion, original/verification audit, missing or unresolved execution,
retained receipt/download rows and outstanding retention work. Even a clear
snapshot is not a retirement permit or protection against later dependencies.
Actual retirement still needs qualified cleanup and restore checkpoints,
transactional dependency fencing, finite replay/privacy horizons and purpose-owned
leaf removal. Descriptive deletion alone retains both metadata charges. No
status, lease expiry or missing execution row refunds uncertain acquisition or
transfer spend.

Tests and fixtures use synthetic inputs. The focused handoff lists commands and
actual results; native qualification is pending. Protected configuration
producers, periodic supervision, retirement and Helm/runtime composition remain
separate implementation work.

## Independent approved-query control

ADR-206 approved reads consume the separate
[query-capacity reservation](context-query-capacity.md), not capture-control rows
or download windows. Polls, credential continuation, first-Pod observation and
source refresh must all fit the exact accepted finite control/history profile.
Queries remain unavailable without original protected acceptance and measured
worker/hub/key/provider backing. Two delivery batches are not a poll limit, and
expiry does not prove cleanup or replenish control allowances.
