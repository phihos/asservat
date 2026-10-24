# ADR-225 — Context capture failure causes

Date: 2026-10-25. Status: implemented; real SQL and installed qualification pending.
Related: [ADR-223](223-lost-regional-completion-reply.md),
[S-02 exit item 2](../architecture/implementation-slices.md#s-02-exit-in-detail).

## Problem

S-02 requires that a lost target and a denied field produce useful states. Every
failed pod-status capture was `Failed`/`AcquisitionFailed`, and a request whose
reviewed Pod had been deleted returned `OutcomeUnknown`, which tells the user to
retry the same preview. That retry can never succeed.

## Decision

1. A started capture whose pinned Pod is gone or replaced records phase
   `targetGone`; one whose pod-status read Kubernetes denied records `denied`
   (migration 00079). Both are terminal like `captureFailed`: no acquisition
   instant and no copies. get_capture reports capture phase `Failed` with action
   phase `TargetGone`/`PinnedPodGone` or `Denied`/`PodStatusDenied`, values the
   get_capture schema already declared.
2. The region sends the cause over the closed operation labels
   `target-changed` and `target-denied`; raw errors still never cross.
3. request_capture for a reviewed Pod that no longer resolves returns the
   catalogued `TargetGone` (not retryable; preview again). Previews keep the
   nondisclosing `NotAvailable`: a preview has not yet disclosed the Pod.

Object-store failure already reports `Indeterminate`/`StorageOutcomeUnconfirmed`
and exhausted capacity `CapacityUnavailable`. A key-service failure before the
start stays `Pending` until the deadline marks it `Indeterminate`; that is not
changed here.

## Complexity gate

1 lost target is common (rollouts); 2 no; 3 typical; 4 Kubernetes reports
`NotFound` the same way; 5 none added; 6 two terminal states, no fallback;
7 no; 8 no; 9 none; 10 additive migration, old rows unchanged; 11 a smaller fix
would leave the failure generic, which the exit criterion rejects.
