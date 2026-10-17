# ADR-152: Current retention audit receipts

Status: implemented in schema 57; component, targeted real SQL/S3 and native
Kubernetes retention reconciliation checks pass. Applies to REQ-PRV-001/002/004,
REQ-EVD-002 and TASK-02/07/11. Full installed-runtime qualification remains pending.
Actual outcomes belong in [implementation progress](../implementation-progress.md).

## Decision

Current retention source authority requires a complete immutable audit receipt
for every retained checkpoint and every lifecycle decision caused by its
catch-up work. An acknowledgement flag or a valid latest checkpoint cannot hide
an older receipt with an empty or `null` version. Preserve original records and
acknowledgements; do not fabricate versions or repeat acknowledgement to repair
history. This applies the accepted required-version storage decision to current
retention authority, including already stored rows.

C-01 retains checkpoint continuity and observation. C-15 retains restrictive
catch-up and lifecycle decisions. Their existing transaction root/source locks,
original five-second bounds, complete LIST watermark, recovery fence and source
identity checks remain mandatory. The receipt checks add no freshness interval.

The current source read uses two partial indexes of invalid receipts. Each
predicate inspects only the row being indexed; the query uses the same exact
predicate. This follows PostgreSQL's requirement that a query imply the partial
index predicate at planning time. [PostgreSQL 18 partial indexes](https://www.postgresql.org/docs/18/indexes-partial.html)

- `retention_checkpoint_invalid_receipt` indexes `(root_id, cluster_id,
  namespace_uid, id)` when acknowledgement is absent or the checkpoint receipt
  fails its fixed validator.
- `retention_decision_invalid_receipt` indexes `(root_id, id)` when acknowledgement
  is absent or the lifecycle receipt fails its fixed validator. Each candidate
  joins one unique catch-up effect and one checkpoint to retain exact source
  scope. The existing completion branch also compares decision root/attempt
  with the original checkpoint/effect.

No Ready cache, new authority writer, history ceiling or generic receipt RPC is
introduced. The existing completion query already scans O(C + E) retained
checkpoints and catch-up effects. These indexes avoid adding full historical
receipt parsing on each effect; they do not make that existing scan constant
cost. Invalid decisions from other sources in the same root can still require
one-to-one candidate joins. Planner-default measurements and the original
source's remaining interval decide availability.

## Closed input predicates and privilege

`public.retention_checkpoint_receipt_current(uuid, uuid, jsonb)` validates only
`retention-acceptance/v1/<root>/<event>/record` receipts up to 512 KiB.
`public.retention_lifecycle_receipt_current(uuid, uuid, bytea)` validates only
`lifecycle/v1/<root>/<event>/record` receipts up to 128 KiB. Both require the five
canonical fields `Key`, `Version`, `ETag`, `Bytes`, `SHA256`; exact original
nonzero root/event; bounded non-control UTF-8 text; a nonempty, non-`null` version;
positive bounded integer bytes; and exactly 32 integer digest octets with a
nonzero digest. Receipt input is bounded at 4096 bytes before bytea decoding.

Both functions are immutable, invoker functions with a fixed `pg_catalog,
pg_temp` search path, explicit UTF-8 conversion and C collation. They read no
relation, configuration or clock, and perform no write. Only SQLSTATE class 22
parse/data errors return false. Cancellation, lock/I/O errors and resource
exhaustion remain query failures. An immutable function's output must depend
only on its inputs; mutable configuration must not enter these predicates.
[PostgreSQL 18 function volatility](https://www.postgresql.org/docs/18/xfunc-volatility.html)

Grant PUBLIC EXECUTE explicitly on these two pure input predicates. This is a
new data-only function capability, not a table grant or privileged operation.
Keep SECURITY INVOKER and do not alter existing runtime role grant inventories.
The current role verifiers check direct grants and ambient security-definer
functions; these predicates fit neither privileged category. Verify catalog
attributes and real read-role execution/acknowledgement denial in the fixture.
[PostgreSQL 18 CREATE FUNCTION](https://www.postgresql.org/docs/18/sql-createfunction.html)

The SQL current parser is deliberately closed. Historical Go JSON decoding can
accept extra or case-folded fields and duplicate members; bytea SQL parsing
rejects these. JSONB has already normalized duplicate keys and some numeric
spellings, so the original encoding cannot be recovered. Canonical product
receipts must agree between Go and SQL; full equivalence on noncanonical input
is not claimed. Historical decoding does not acquire current authority.

## History, migration and verification

`HistoricalRetentionAcceptance` preserves the previous structural receipt
checks for restart, exact checkpoint replay and restrictive catch-up. It grants
no current source authority. `AcceptedRetentionSource` additionally checks the
actual current receipt with the strict domain predicate; indexed history checks
cover earlier checkpoints and decisions. Known historical obligations continue
to shorten evidence lifetimes while invalid audit history blocks new authority.
Independent physical version/delete-marker inventory and retirement are unchanged.

Migration builds the derived indexes from existing rows without rewriting any
receipt. Invalid old rows become unavailable to current reads. There is no
inverse migration deleting this history. A later predicate semantic change must
rebuild its affected indexes in an additive migration; replacing the function
alone could leave stale index membership.

Qualification must include the original empty/null failures; canonical parser
boundaries and malformed bytea; actual SQL/S3 earliest-invalid/latest-valid and
completed-lifecycle history; foreign root/attempt joins; exact full-row restore;
restrictive catch-up under old receipts; and read-role mutation denial. Run
planner-default EXPLAIN ANALYZE with synthetic histories of 1, 256 and 4096 rows,
recording the old completion baseline, index use, actual rows/loops/buffers and
elapsed time. These synthetic rows never confer application authority. Measure
migration/index build cost separately. No bounds or query planner switches may
be changed to manufacture a passing result.
