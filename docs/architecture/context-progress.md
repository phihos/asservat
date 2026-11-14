# Context capture progress

C-09 `ContextProgressService.Get` serves `get_capture` under
[ADR-105](../decisions/105-durable-context-progress.md). Browser and MCP use the
same application DTO. It is control metadata: no evidence bytes, reasons,
commands, credentials or hidden sharing recipients.

## Read

The service takes the request-owned `CurrentIdentity` and authorizes once per
operation ([ADR-311](../decisions/311-operation-authority-recheck.md)):
requester or scoped-maintainer rights on the capture's immutable target.
Absent and unauthorized captures return the same denial. One MVCC select
combines admission, execution, custody and publication; it takes no locks.

| Durable facts | Capture and action phase | Reason |
| --- | --- | --- |
| Accepted, no recorded start | Pending | DispatchUnconfirmed |
| Start recorded, no outcome | Running | AcquisitionStarted |
| Stored outcome awaiting publication | Finalizing | PublicationPending |
| Published catalog entry | Succeeded | Published |
| Original deadline passed, no publication | Indeterminate | DeadlineOutcomeUnconfirmed |

Publication is historical: expired or deleted evidence can still show a
Succeeded capture. Case navigation independently establishes current access
and omits the link on failure. `can_cancel` is false for this profile.

## Change delivery

Admission, execution, custody and publication transactions advance
`progress_revision` and issue `NOTIFY capture_progress, '<capture-id>'`. The
hub API listens and pushes the new projection to the page's SSE stream; MCP
`get_capture` with a known revision waits server-side up to 30 s and returns on
the first change. After a reconnect a listener catches up with one query by
revision. Clients do not poll.

`deadline_observed_at` marks unpublished captures whose original deadline has
passed. The hub worker keeps one timer to the earliest such deadline from an
index, marks the due rows in one statement, notifies and re-arms; insertions
with an earlier deadline wake it by `NOTIFY`. The mark is SQL-timed and
immutable. It does not refund capacity or infer Failed/TimedOut; it reports
Indeterminate until the idempotency-key lookup or a late receipt resolves the
outcome.

## SQL

`progress_revision`, `deadline_observed_at` and their partial index live on
the capture row; fixed triggers in the writing transactions advance the
revision. The hub API and hub worker use their single SQL logins; neither can
change scope, deadlines or publication through these columns.
