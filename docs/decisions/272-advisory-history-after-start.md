# ADR-272 — Advisory history after the start, with its own budget

Date: 2026-10-31. Status: accepted by the maintainer; unit tests pass,
installed qualification pending.
Requirements: specs/recording-saves.md (repeat via fresh selection), S-04.

## Context

A single Save request persisted advisory history before its start
(`c267cde7`), so a start that used its whole bound could not starve history.
Both shared the start's five-second bound. Installed native run 41195635505
showed the reverse: a slow history exchange left the start under one second
and ADR-212 headroom refused it (`AcquisitionClosed`). History also took the
regional standby the start then waited for.

## Decision

1. Starts take priority on every path (single and group): advisory history
   runs after the start.
2. History gets its own deadline: at most ten seconds (`historyBudget`)
   from when it begins, never beyond the original request window
   (`RecordingSaveRequestWindow`, the caller's identity validity and the
   caller's context). It is not limited by the start's narrowed bound.
3. A refused history attach is retried every 250 ms while at least four
   seconds remain: right after a start a standby may be reopening (native
   run 41199782289), and the recording collect holds the capture's route and
   the cluster's capture slot for its short exchange (native run
   41211070820).
4. History attaches without waiting inside the attach (`TryAttach`), and
   its attachment may last up to ten seconds instead of five: the receiver
   check, SQL claim and three-copy exchange exceeded five seconds on CI
   (native run 41215337179). The claim and settlement use a recovery
   observation read just before them.
5. History ends one second before the original request window, and the
   accepted reply's identity check and metadata re-read then use that window
   rather than the start's narrowed bound, as group Saves already did
   (native run 41227724909: the reply expired after history).
6. History remains advisory: its outcome never changes admission or the
   start's result, and Persist keeps every recovery, retention, SQL identity
   and accepted-deadline check.

## Consequences

A slow start no longer starves history and slow history no longer starves
the start. A request can take up to ten seconds longer before replying,
still inside its original window. Replay still never writes history.
