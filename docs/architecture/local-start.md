# Start consumption

C-07/C-11/C-20/C-21/C-24 under I-02, TASK-03/05 and S-01/S-02; part of REQ-FED-002, REQ-CAP-002/005 and REQ-ARC-003/004. Design follows [ADR-330](../decisions/330-event-driven-system-design.md) D7/D8.

An intrusive `onTrigger` effect starts at most once. The start right is one hub SQL row, `capture_start`, keyed by the attempt ID (the effect's idempotency key). It records operation/capture/action/attempt, target Pod (and node for node execution, executor Pod for the [regional API profile](api-context-runner.md)), scope and budget digests, native-byte limit and the original start interval (at most 60 seconds). No evidence, reason, command, token or key enters the row. There is no Kubernetes object per attempt.

## States

1. **Ready.** Admission writes the row after the workload charge succeeds ([custody](custody-transactions.md)), in the same transaction.
2. **StartCommitted.** The executor consumes the right with one conditional update before any effect:

   ```sql
   UPDATE capture_start SET state = 'StartCommitted', committed_at = clock_timestamp()
    WHERE attempt_id = $1 AND state = 'Ready' AND clock_timestamp() < start_not_after
   RETURNING attempt_id;
   ```

   One returned row is `MayStart`. Zero rows means the right was already consumed, expired or never existed; the caller reads the row to learn which.
3. **Terminal.** Completion, failure or expiry records the outcome and releases unused charges (D7).

The executor reaches this update through its existing connection: collector → connector stream → hub. The connector keeps per-attempt state only in memory, keyed by the operation ID, and rebuilds it from the hub after a restart. A lost reply is resolved by reading the row by attempt ID. Only the reply of the successful update authorizes the effect; a later read of `StartCommitted` never does. A crash between consumption and the effect may lose evidence; it never justifies a second start.

`StartCommitted` means only that the right was consumed. It does not prove that a process began, a capture succeeded or evidence was committed. The executor still checks the returned deadline immediately before the effect and holds local process exclusion. No HTTP handler accepts an arbitrary `execution.Request` as authority.

Rows follow the capture's audit-retention partitioning; no separate cleanup is needed.

## Profiles

| Profile | Executor | Native types |
| --- | --- | --- |
| `onTriggerStart/v1` | Node collector; binds node and target Pod | Action-specific |
| `apiContextStart/v1` | Regional API executor; no node fields | `pod-status`; `logs` up to 64 MiB |
