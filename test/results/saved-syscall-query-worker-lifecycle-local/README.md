# Exhausted projection worker completion and positive early retirement

Signed `5c4fc02ee36c6f1246f19b301b84404aa91b2980` implements ADR-307. Only a
locally authenticated single-batch/generation-one projection can finish after
its exact final joined ACK and successful joined shutdown. Multi-batch/native
download/uncertain paths retain original behavior and dates. Review caught an
independent credential failure being masked by successful work; its overlay RED
and corrected50-run race GREEN are preserved. Actual caller cancellation is
reported at its credential-supervisor origin; genuine original expiry remains.

Existing SQL closed/native-closed/query/worker/claim/reference facts gate early
eligibility and fresh worker-locked confirmation. Exact positive Job/Pod proof,
UID deletion/absence and persisted retirement remain necessary. The existing
runtime role gains EXECUTE only on a pure IMMUTABLE batch-count helper; no new
role, table, schema, timer/watch or logical refund is added. Early foreground
cleanup adds existing bounded API walks (maximum44 resource calls/attempt plus
unchanged guards), not a background poller.

Pristine actual-role baseline RED fails as intended after join because the old
selector omits the completed worker. The first corrected campaign fails in a
fixture diagnostic's misspelled table after selection; that is retained as FAIL,
not a product or successor success. After the one-token correction, single-batch
retirement and actual successor lifecycle pass in11.567s; a separate pristine
two-batch control passes9.247s and stays charged before original RunUntil. Both
have testExit0, unchanged source and cleanup[]. Two independent audits and Root
match all4,231 Git blobs per final run. Physical/issuer/transport/crypto proofs
supplied by these SQL fixtures remain explicitly synthetic; no independent
uncertain-row real-service lifecycle was produced. Lost ACK/close/cancel controls
have separate real-TLS evidence and the SQL no-uncertainty predicate is reviewed.

Root make pre-push exits0 (561 tests/49 console files). The complete compiled
console-browser gate exits0 in118.349s across8 top-level fixtures, including
actual syscall authoring, original approval receipt and native restart controls.
Its authority/provider services are synthetic. Generated tracked screenshots
and JSON were preserved here before restoring their old baselines. The manifest
retains original failures, source overlays, final inputs, reports and exact gate
logs; generated untracked service files were removed only after byte verification.

No measured installed resource saving, fresh physical Kubernetes/SQL retirement
composition or complete20-minute syscall workflow pass is asserted. Those remain
the next frozen qualification. Original budgets/expiry proof/views/Repeat/Stop
are retained.

A final cache-only stress variant lets the generic credential callback return
`context.Canceled` independently while its supplied context remains live. It
returns incorrect success in46/50 repetitions; this is retained as a failing
synthetic callback-contract audit. The sole production callback uses the actual
credential supervisor: enrollment errors are retried/reclassified, and its
cancellation returns come from its supplied context or the production wait on
that context. No independently cancelled production path was identified. This
boundary does not justify a claim that arbitrary credential callbacks are safe.

The final actual-supervisor regression and natural-completion races pass in
1.060s. Final spec/architecture and diff checks pass. These follow-up changes
add a runtime comment and a regression; earlier full gate/service evidence
retains its exact5c4fc02e source binding. The final three source snapshots are
archived separately rather than rewriting that earlier binding.
