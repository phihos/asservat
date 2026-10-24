# Initial download authority handoff qualification

The runtime performed a complete authority evaluation during `beginRequest`, discarded its result, then immediately evaluated the same authority again before its first attachment SQL read. Only synchronous validation and configuration copying separated those checks. The component regression measures that path through `ContinueContextDownload` and stops at the first worker reservation, without SQL, provider work, or Job creation.

The correction hands the exact initial observation to the immediate first read, clips it to all original bounds, and revalidates cancellation, current time including owner-clock rollback, scope, environment path, and worker profile. The compatibility constructor remains eager. Every later authority evaluation after blocking work remains current; no cache, deadline renewal, retry, or effect-budget change was introduced. The three call sites are continuation, prepared metadata, and response chunk reads.

| Check | Actual exit | Go package duration | Scope |
| --- | --- | --- | --- |
| RED, before production changes | 1 | 0.006s | Duplicate measured as two checks before first SQL and three before reservation; deterministic 1.7s-per-check case expired before reservation. |
| Intermediate focused race | 1 | 0.048s | Production regression passed; new rollback test setup failed because nested proof observations did not predate the owner. Raw failure is retained. |
| Final focused race | 0 | 1.047s | Corrected rollback setup; all new cases passed. |
| Full evidence package race | 0 | 3.896s | All 2,582 Go source hashes unchanged before/after. |

Each run's JSON contains exact argv, environment, working directory, timestamps, actual exit, wall time, and source hashes; the corresponding log is raw combined stdout/stderr. `verification.json` summarizes existing verbose-log test counts; the full package run was not verbose, so no test count is inferred. `snapshots.txt` identifies exact RED and final GREEN copies. The failed intermediate test snapshot was not retained; its measured hash and raw output remain available.

Negative coverage preserves caller, identity, authority, session, and source cutoffs; source expiry during initial authority; invalid scope/profile/current path; owner-clock rollback; cancellation with joined blocking authority/attachment work; and revocation, changed identity, expiry, and cancellation during attachment I/O before reservation.

This is deterministic component evidence for an adjacent duplicate check. It does not establish that the duplicate caused the installed native50 failure, qualify a new external installation, or replace downstream disclosure, publication, transfer, revocation, retention, or deletion gates. No external fixture was run for this patch.

Independent read-only review found no blockers in the frozen four-file patch; see `independent-review.md`. No duplicate tests were run. This verdict covers the adjacent duplicate removal only; the full dispatch phase still requires separate budget analysis before another installed qualification.

The parent subsequently ran `make spec-check architecture-check go-architecture-check design-check` with the existing format-enabled validation environment: exit 0 in 11.054 seconds. `parent-gates.json` and `parent-gates.log` retain the exact command, source hashes and output. The seven selected implementation, test and documentation files were unchanged during this run. These design/architecture gates do not replace the pending final repository Go gate or installed workflow qualification.
