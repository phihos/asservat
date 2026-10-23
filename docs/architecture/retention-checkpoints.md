# Durable retention policy checkpoints

C-01 owns source acceptance under REQ-PRV-001–003, TASK-02/07/11 and S-01/S-02. C-15 owns effective evidence deadlines and retained-artifact reconciliation. These packages implement persistence and encrypted audit of policy history; they do not yet produce a Ready policy source or authorize public collection/download.

## Initial values

An installation accepts its initial complete retention-policy set against a currently qualified write-protection digest. Existing values require a protected, independently pinned ConfigMap with exactly six string fields: `format: asservat-retention-bootstrap/v1`, `reviewer`, `policiesSHA256`, `protectionSHA256`, `reviewedAt`, and `expiresAt`. The two hashes bind the full canonical source snapshot and the exact installed protection. Review validity is at most one hour; reading the object yields an independent observation interval of at most five seconds. Namespace and ConfigMap UIDs are pinned. The reviewer field records provenance and grants no role.

An empty source needs no review of nonexistent values. An empty hub still cannot resolve retention without its baseline. This is installation acceptance, not a new approval for each policy edit or evidence capture. Normal edits go through the guarded Kubernetes API and ordered watch history. Guard changes require explicit source requalification; restarting the reconciler cannot replace an accepted guard or clear a recovery block.

The Kubernetes reader depends on installation protection of its ConfigMap from delegates, status writers and application maintainers. A successful GET does not establish those writer restrictions. Production enrollment/installation composition must establish them independently.

## Durable transition and restart

Migration `00015_retention_sources.sql` adds a pinned source identity, non-reusable process epochs and immutable checkpoints. Source keys include installation root, enrolled cluster and control namespace UID; hub origin and protection digest cannot be rewritten. Sequence numbers increase across process restarts, not only within an epoch. One active controller holds a 30-second lease; another epoch cannot take over until suspension or expiry. An old epoch cannot suspend or renew its successor. Recovery blocking is outside runtime reconciliation privileges.

Each checkpoint records the complete bounded policy state, opaque watch cursor, per-policy resource versions and deletion-in-progress state. The initial transition is checked against its finite review. Later transitions replay exactly one typed event against the preceding durable state, binding the previous checkpoint digest. A fresh LIST cannot replace skipped history. The store rechecks leases after blocking locks and writes. Exact request replay returns the original historical record and does not renew authority. A conflicting reuse of an ID fails.

Expired policy observations can be replayed to retain obligations after downtime. `HistoricalCheckpoint` and `ResumeRetentionJournal` explicitly support this; they do not refresh the observation clock. `Checkpoint(now)` continues to reject a stale source. Losing watch history, including an API 410, still requires recovery rather than silently accepting a new final LIST. A lower-then-higher maximum remains two independent checkpoints. Deletion state also survives restart, preventing a resumed stream from accepting a cleared deletion flag.

The SQL lock order for accepting configuration is installation permission-root, then retention source. This serializes source changes with the existing root-based capture/disclosure transactions. Public production gates must additionally verify the complete required source set and catch-up barrier in their transaction; acquiring the root lock alone does not do that.

## Audit and catch-up boundary

`RetentionReconciler` connects the concrete guard, typed Kubernetes LIST/watch, initial review and durable store. First acceptance checks protection before and after the initial reads. Restart resumes the durable cursor without fetching a replacement initial LIST or requiring another review. Every event, including resumable bookmarks, is persisted before its successor. A bounded watch queue and per-event protection deadline prevent unbounded processing and permit extension. Periodic guard checks stop the controller if protection disappears; process cancellation or failure suspends the epoch. Clean watch EOF resumes from the last durable cursor; history errors stop rather than reset it. The follower separately submits fresh complete LIST/guard observations against their original deadline. The store requires watch progress through the LIST watermark and exact per-object agreement; a bookmark or active lease alone cannot renew availability.

Each transition atomically appends a minimized acceptance record. It contains source/epoch/sequence, protection and checkpoint digests, prior digest, policy revision identities, and initial-review provenance. It contains no workload labels, policy purpose text or captured evidence. A separate audit role writes it to a purpose-bound encrypted create-only object, reads and authenticates that object, and acknowledges the exact receipt. Retries reconcile a successful write with a lost response. Acknowledged receipts and checkpoint content are immutable.

The SQL source runtime cannot acknowledge audit, modify custody deadlines, clear recovery, replace source protection or delete history. The audit runtime cannot alter source state or checkpoint content. The fixture roles exercise these boundaries; production credential provisioning remains separate work.

Multiple pending checkpoints remain independent durable obligations. Audit acknowledgement is not retained-evidence catch-up. There is no Ready setter. Migration 00018 adds finite current observations and a separate `RetentionSourceReader` facet, deriving source availability from ordered application to every candidate retained context artifact, every source/lifecycle audit receipt, the current guard, the complete LIST watermark and the source restore fence. Public use still needs protected complete topology, historical selector facts and acquisition/disclosure transaction composition. See [ADR-056](../decisions/056-retention-watch-watermark.md).

Metadata retention/backup cleanup, signed remote policy propagation, automatic checkpoint supervision and full historical selector qualification remain required. The bounded context catch-up producer is described in [retention catch-up](retention-catchup.md). Existing lifecycle signatures cover individual artifact deadline changes; this encrypted acceptance record is not a signed remote policy authorization.

## Verification

The initial-review and historical replay unit/race tests pass in `test/results/retention-bootstrap-unit.log` and `test/results/retention-checkpoint-unit.log`. They cover exact values/protection, namespace/object replacement, stale and overlong reviews, history gaps, relist substitution and deletion-state recovery.

The full SQL/S3 suite passed with exit 0 in `test/results/retention-source-integration-check.log` (Go integration run: 45.256 seconds). It exercised eight-way duplicate acceptance, restart between lower/raise transitions, exclusive/non-reusable epochs, current recovery blocking, lock-wait expiry, immutable checkpoints, exact encrypted write/receipt replay and SQL role separation. The source-hashed environment report records unchanged tested source and no cleanup failures. Guard/bootstrap inputs in this fixture are synthetic, and no source is promoted to Ready.

The subsequent real Kubernetes/PostgreSQL/S3 composition passed with exit 0 in `test/results/retention-reconciler-kubernetes-check.log` (admission Go run: 13.510 seconds). It uses the real pinned guard, read/watch client, protected ConfigMap review, SQL runtime/audit roles and encrypted object writer. Delegate/status/reader roles cannot rewrite the review. The test stops the reconciler, removes the no-longer-required review object, lowers and raises the policy through the actual API, then resumes the durable cursor and verifies both transitions in SQL and object audit. Loss of the pinned guard stops reconciliation. Source hashes remained unchanged and all owned fixtures were removed. Test key wrapping and installation provisioning remain synthetic; this is not a Ready-source or public-workflow test.

`test/results/retention-source-gates.log` records passing Go/race/import/sqlc/specification/architecture/design gates for the checkpoint store. `test/results/retention-reconciler-unit.log` records passing race tests for the subsequent follower.

## Finite complete observations

Migration 00018 adds `observed_sequence`, `observed_at` and `fresh_until`. Observation acceptance locks the installation root/source, validates the original guard and LIST interval, compares same-resource watch progress against the LIST watermark, and checks exact per-policy state. Discovering changed final policy state commits invalidation immediately while reporting a retryable catch-up condition. A higher LIST watermark with identical final objects cannot renew freshness, but preserves the preceding observation until its original deadline. The highest accepted or known-changing LIST watermark survives invalidation/restart and prevents older delayed replies from restoring availability. The follower keeps at most five original LIST/protection observations, obtaining at most one per second. It confirms the freshest covered watermark, discards older/expired entries and never refreshes their times. Observation processing never changes immutable checkpoint provenance. Since the ADR-200 revision (2026-10-23, migration 00075) an accepted observation is stored for 30 seconds after its original LIST/guard start (`privacy.RetentionSourceInterval`) and keeps the source lease that long; the LIST and guard must still be within their five seconds when written, and invalidation, suspension and takeover still clear it at once.

The separate SQL reader requires the current source epoch, observation at the current sequence, every completed catch-up page and every source/lifecycle receipt. All checks run under root/source locks and recheck time before returning. New policy events, suspension and restart clear observations; bookmarks leave their times unchanged. Reader credentials cannot alter observation, completion or receipts. The hub source also requires exactly one baseline. This is source availability, not authorization to collect or read an artifact. Topology, target/selector protection, fleet/restore gates and the final operation transaction still apply.

Refresh scheduling now uses the remaining interval from the last observation start, including across watch reconnection. The regression `TestRetentionRenewalDoesNotSkipCycleAfterGuardTimingShift` first reproduced a 1.88-second interval from a 120 ms guard-call shift; it passes after replacing the independently phased ticker with an observation-based timer. A rollback fails closed before another source read. The one-second minimum spacing, five-second original proof lifetime, bounded pending window and complete history requirement remain unchanged. Real fixture failures retain bounded timing traces; successful short runs do not establish a provider watch-latency guarantee.

## Current immutable audit history

[ADR-152](../decisions/152-retention-current-audit-receipts.md) separates structural
checkpoint history from current authority. Current reads require nonempty,
non-`null` versions in the actual latest receipt and every earlier checkpoint or
catch-up decision. SQL57's proposed partial indexes classify invalid receipt
rows with fixed pure invoker predicates; PUBLIC EXECUTE permits input validation
only and grants no table access. The complete-history completion scan remains;
indexing receipt failures is not a constant-cost availability claim.

Restart and restrictive catch-up retain the original structural history decoder.
They never synthesize a version, rewrite acknowledgement or promote an old
receipt. New audit effects and current authority require strict receipts. This
source implementation still requires component, migration, query-plan and native
qualification; earlier recorded checkpoint tests do not qualify this change.
