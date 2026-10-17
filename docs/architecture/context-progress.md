# Context capture progress

The shared C-09 `ContextProgressService.Get` supplies the first bounded
`get_capture` use case under [ADR-105](../decisions/105-durable-context-progress.md).
Browser and MCP adapters use the same application DTO. This is control metadata;
it contains no evidence bytes, reasons, commands, credentials or hidden sharing
recipients.

`ContextProgressReads` is a separate PostgreSQL facet. It locks current recovery
before the permission root, reads immutable capture routing facts internally,
and evaluates current requester or scoped-maintainer rights before joining
lifecycle facts. Absent and unauthorized captures return the same denial.
A single MVCC query then combines admission, custody, semantic verification,
audit acknowledgement and publication. Original scope and registration digests
must agree. It checks the earliest original identity, permission, recovery and
five-second read deadline after all blocking database work.

| Durable facts | Capture and action phase | Reason |
| --- | --- | --- |
| Accepted intent awaiting audit | Pending | IntentAuditPending |
| Audited intent without stored outcome | Pending | DispatchUnconfirmed |
| Stored outcome without semantic verification | Finalizing | VerificationPending |
| Verified outcome awaiting audit acknowledgement | Finalizing | VerificationAuditPending |
| Audited verified outcome awaiting publication | Finalizing | PublicationPending |
| Matching audited verified catalog publication | Succeeded | Published |
| Original deadline observed, no publication | Indeterminate | DeadlineOutcomeUnconfirmed |

Publication is historical. Expired or deleted evidence can still have a
Succeeded capture outcome under the finite control-metadata policy; the case
navigation port must independently establish current access. Its failure omits
the link. No artifact reference is automatically exposed from the private
candidate identifiers. This implementation always returns `can_cancel=false`;
Pending and Finalizing suggest polling after two seconds.

The application service accepts request-owned `CurrentIdentity`, not a
caller-selected actor or browser-only session. It preserves the original
identity/recovery/read interval through optional navigation and final identity
resolution. Browser and MCP envelope/schema validation remain transport-owned.

Migration 00034 adds `progress_revision`, `deadline_observed_at` and one partial
index without adding tables. Existing intent, custody, verification and catalog
transactions update revisions through fixed triggers. The overflow sentinel
1,000,000,001 denies public progress without rolling back privacy transitions.
There is no use of `xmin`, data hashes or process-local counters as revision.

`ContextDeadlines.ObserveOverdueContextCaptures` is a distinct bounded mutation
facet, called by future protected supervision. It locks the permission root and
marks at most sixteen unpublished admissions whose original deadline elapsed.
The timestamp is SQL-assigned, immutable, and does not establish writer
quiescence, refund capacity or change accepted identities. Multiple workers
serialize safely; retry cannot produce another transition. A stopped observer
leaves the last durable phase visible. This is explicit operational uncertainty,
not an automatically inferred Failed/TimedOut/Running status.

The read SQL role can SELECT the relevant projections and take the existing
identity-column root locks. The deadline role can update only its timestamp
column. Neither can change original scope, deadline, intent audit, revision,
custody or publication. The migration owner owns the fixed SECURITY DEFINER
revision function, whose pinned trusted search path and revoked public EXECUTE
are described in ADR-105. Runtime roles cannot attach arbitrary triggers.

Targeted Go unit and race tests cover requester/client identity, ordinary scope,
complete-deny checks, publication integrity, overflow, preserved original
freshness, cancellation and separately authorized navigation. The native
fixture source adds real SQL role denials, API-only admission/replay, concurrent
once-only deadline observation, retained uncertain storage charges, actual
retention shortening at revision exhaustion, and verification/audit/publication
revision transitions. Native qualification must be recorded after the owned
custody suite runs; compiling/skipping that fixture is not a passing SQL run.

Pending composition includes overdue supervision, protected capability
production, case navigation, distributed execution/publication and public
runtime/bootstrap. Historical-row retirement and admission fairness are tracked
separately by U13 and are not solved by this projection.
