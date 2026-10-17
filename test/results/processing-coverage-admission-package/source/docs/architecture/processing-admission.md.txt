# Processing coverage at context admission

[ADR-146](../decisions/146-processing-coverage-before-collection.md) adds a
current pre-collection check to C-09 and the existing C-21 admission transaction.
It implements REQ-CAP-005 and REQ-EXE-002 for the fixed pod-status slice.

The proposed original artifact location, exact target, acquisition anchor and
resolved deletion date enter `ContextProcessingCoverageReader`. Its concrete
implementation is `postgres.ProcessingReads`, using the existing purpose15
processing read credential, recovery guard and bounded SQL transaction. It
checks original installation/issuer/root/source/initialization, qualified
backing, counters and the full bounded active-rule inventory, then reads the
root again. Changed state, malformed rows, cancellation and expired original
bounds fail unavailable. Matching retained restrictive rules keep their original
horizon; root renewal cannot change those dates. The result retains the earliest
caller, recovery, initial five-second read and root cutoff after commit.

Preview checks coverage before persisting its draft. New submission resolves
accepted same-key history first; only an absent original request proceeds to
fresh retention, storage and processing checks. Neither the observation nor its
freshness enters approval digests. Retention stays exactly as selected through
the existing resolver; this check never shortens it.

SQL54 managed admission repeats the check while holding the existing permission
root, before custody registration and control/capture/audit inserts. Purpose40
adds SELECT on exactly `processing_root` and `processing_rule`; it gains no
processing mutation or source privileges. The finite managed-admission result
selects this branch, rather than any caller flag. Legacy unmanaged account
semantics stay unchanged. Final freshness checks precede commit.

The serialization order is established by supported writers:

- `ProcessingConfiguration.AcceptCurrent`: recovery, permission, processing
  root, then insertion or exact backing update.
- `ProcessingDecisions.transaction`: recovery, permission, processing root,
  exact decision/rule; apply obtains the processing audit pool before the
  immutable audit row. Nested rule/decision triggers retain this order.
- Catalog publication: its effect transaction already holds recovery and
  permission. SQL50 `project_context_processing` takes permission then processing
  root before lineage insertion and the counter update.
- SQL54 root reserve/renew: `capacity_lock_root_observation` takes recovery,
  permission and source before backing locks. Renewal joins the bounded retained
  configuration before updating the processing root. It preserves rule dates.
- SQL50 rejects root/rule deletion. Its row triggers repeat permission checks,
  but a BEFORE row trigger alone cannot establish order ahead of an arbitrary
  SQL statement's implicit tuple lock. The supported scoped writers acquire
  permission first; direct administrator SQL is not a runtime path.

Admission uses nonlocking processing reads under that shared serialization
point. It does not acquire a late processing-row lock behind the audit/storage
locks. Read-only preview instead detects an intervening root change and fails;
it makes no reservation. In particular, the published `captures` counter does
not include pending captures, so a positive preview is not a promise that the
final lineage slot remains available. Publication always rechecks independently.

Known insufficient coverage has a shared browser/MCP message distinct from a
transient unavailable read. A request failure preserves original-key recovery
and uncertainty about an earlier accepted attempt. No new authority, automatic
retry, retention choice or public collection enablement is introduced.

The production public graph has no `ContextInvestigation` constructor yet. Its
installed composition must supply the original purpose15 reader; neither the
application fixture nor the real SQL native helper supplies that missing
installation boundary. Constructor sites are inventoried in the handoff.

The source and native tests for this follow-up remain unrun until recorded by
the owned qualification harness. The existing SQL54 matrix passed before this
change; it is not evidence for these added checks.
