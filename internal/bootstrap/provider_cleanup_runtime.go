package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	auditapp "asservat.local/asservat/internal/application/audit"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
)

// Scheduling queries carry no native/effect authority and do not acquire a
// FIFO ticket. Each selected row is independently checked by its actual SQL
// transaction after admission; the page is never a retained permit.
func (d *CaptureCleanupWorkerDeployment) runProviderCleanup(ctx context.Context) error {
	cursor := ""
	report := eventLog(os.Stderr, "operation cleanup")
	report("started")
	for ctx.Err() == nil {
		operationsStarted := time.Now()
		schedule, end := context.WithTimeout(ctx, 5*time.Second)
		ids, err := d.journal.DueWorkerOperations(schedule, cursor)
		end()
		if err != nil || len(ids) > 16 {
			if err == nil {
				err = mounts.ErrUnavailable
			}
			err = &cleanupRuntimeError{"due-lifecycles", err}
			report(cleanupRuntimeEvent(err))
			return err
		}
		if len(ids) == 0 {
			report("due-lifecycles/empty")
		}
		pending := false
		operationsAttempted := 0
		for operationsAttempted < len(ids) {
			groupEnd := min(operationsAttempted+2, len(ids))
			group := ids[operationsAttempted:groupEnd]
			attempted, effectErr, current := d.advanceProviderCleanupGroup(ctx, group, report)
			operationsAttempted += attempted
			if !current || attempted < len(group) {
				report(cleanupRuntimeEvent(effectErr))
			}
			if !current {
				return effectErr
			}
			pending = pending || effectErr != nil
			if attempted < len(group) {
				break
			}
		}
		cursor = cleanupLifecycleCursor(cursor, ids, operationsAttempted)
		operationsElapsed := time.Since(operationsStarted)
		historyStarted := time.Now()
		schedule, end = context.WithTimeout(ctx, 5*time.Second)
		keys, err := d.journal.DueOperationHistory(schedule)
		end()
		if err != nil || len(keys) > 16 {
			if err == nil {
				err = mounts.ErrUnavailable
			}
			err = &cleanupRuntimeError{"due-history", err}
			report(cleanupRuntimeEvent(err))
			return err
		}
		historyAttempted := 0
		if len(keys) > 0 {
			var effectErr error
			var current bool
			historyAttempted, effectErr, current = d.releaseProviderHistoryPage(ctx, keys)
			report(cleanupRuntimeEvent(effectErr))
			if !current {
				return effectErr
			}
			pending = pending || effectErr != nil
		}
		// One numeric aggregate per completed nonempty sweep. Include each due
		// query and all serial processing, excluding the fixed idle sleep. IDs,
		// error text and provider inputs never enter these diagnostics.
		if len(ids)+len(keys) > 0 {
			fmt.Fprintf(os.Stderr, "operation cleanup: sweep operations_selected=%d operations_attempted=%d operations_ms=%d history_selected=%d history_attempted=%d history_ms=%d\n", len(ids), operationsAttempted, operationsElapsed.Milliseconds(), len(keys), historyAttempted, time.Since(historyStarted).Milliseconds())
		}
		d.mu.Lock()
		d.lastSweepPending = pending
		d.mu.Unlock()
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return ctx.Err()
}

func (d *CaptureCleanupWorkerDeployment) beginProviderCleanup(ctx context.Context) (*kube.WorkerProjectionOperation, *fleetapp.WorkerRuntimeAdmissionLease, error) {
	lease, err := d.admission.WaitCleanup(ctx)
	if err != nil {
		return nil, nil, err
	}
	op, claim, err := d.reader.BeginCleanupProjectionOperation(lease.Context())
	if err != nil {
		lease.Release()
		return nil, nil, err
	}
	if !reflect.DeepEqual(claim, d.claim) {
		op.Close()
		lease.Release()
		return nil, nil, mounts.ErrUnavailable
	}
	return op, lease, nil
}

// The native cleanup claim is installation/credential scoped, not operation-ID
// scoped. Two exact lifecycle IDs share only that original native bracket;
// their SQL/application effects and remote provider borrows remain independent.
func (d *CaptureCleanupWorkerDeployment) advanceProviderCleanupGroup(ctx context.Context, ids []string, report func(string)) (attempted int, err error, current bool) {
	step := "lifecycle-group-input"
	defer func() {
		if err != nil {
			var stopped *cleanupRuntimeError
			if !errors.As(err, &stopped) {
				err = &cleanupRuntimeError{step, err}
			}
		}
	}()
	if !validCleanupLifecycleGroup(ids) {
		return 0, mounts.ErrUnavailable, false
	}
	step = "provider-refresh"
	if d.providers == nil {
		return 0, mounts.ErrUnavailable, false
	}
	// Credential maintenance precedes this group's native admission, and never
	// extends its context or caches S3/crypto effect authority.
	if err := d.providers.RefreshCleanup(ctx); err != nil {
		return 0, err, ctx.Err() == nil
	}
	step = "projection-begin"
	op, lease, err := d.beginProviderCleanup(ctx)
	if err != nil {
		return 0, err, false
	}
	defer lease.Release()
	defer op.Close()
	step = "lifecycle-group-work"
	attempted, err = advanceCleanupLifecycleGroup(op.Context(), op.FreshUntil(), ids, func(call context.Context, id string) error {
		effectErr := d.advanceProviderCleanupOperation(call, id)
		if report != nil {
			report(cleanupRuntimeEvent(effectErr))
		}
		return effectErr
	})
	if final := op.Finish(op.Context()); final != nil {
		return attempted, &cleanupRuntimeError{"projection-finish", final}, false
	}
	// Unknown/failed row effects stay pending and charged. The next independent
	// SQL invocation alone decides what an original row can still complete.
	return attempted, err, true
}

func (d *CaptureCleanupWorkerDeployment) advanceProviderCleanupOperation(ctx context.Context, id string) (err error) {
	step := "lifecycle-read"
	defer func() {
		if err != nil {
			err = &cleanupRuntimeError{step, err}
		}
	}()
	state, err := d.journal.ReadOperationLifecycle(ctx, id)
	if err == nil {
		b := state.Intent.Lifecycle
		switch {
		case state.TerminalAcknowledged:
			step = "finalize"
			err = d.finalizer.RetireOperationAudit(ctx, id)
		case b != nil && b.Policy.OverdueTerminal == value.OperationOverdueTerminal && !state.CertificateStarted && state.CertificateWriter == nil && state.CertificateReceipt == nil && !time.Now().Before(b.CertificatePurgeAt.Add(-time.Duration(b.Policy.ProofWindowSeconds)*time.Second)):
			step = "overdue"
			err = d.overdue.Advance(ctx, id)
		default:
			step = "healthy"
			err = d.healthy.Advance(ctx, id)
		}
	}
	return err
}

func validCleanupLifecycleGroup(ids []string) bool {
	if len(ids) == 0 || len(ids) > 2 {
		return false
	}
	for _, id := range ids {
		if !authorization.UUID(id) {
			return false
		}
	}
	return true
}

// A partial page must retain its unattempted suffix, including a zero-work
// group. Only a fully processed short page proves the cursor may wrap.
func cleanupLifecycleCursor(cursor string, ids []string, attempted int) string {
	if attempted > 0 {
		cursor = ids[attempted-1]
	}
	if attempted == len(ids) && len(ids) < 16 {
		return ""
	}
	return cursor
}

// The group uses no fresh end. Reserve the final second of the earliest
// original parent/native deadline, then stop before attempting another ID.
func advanceCleanupLifecycleGroup(ctx context.Context, until time.Time, ids []string, advance func(context.Context, string) error) (attempted int, err error) {
	if ctx == nil || until.IsZero() || advance == nil || !validCleanupLifecycleGroup(ids) {
		return 0, mounts.ErrUnavailable
	}
	if outer, ok := ctx.Deadline(); ok && outer.Before(until) {
		until = outer
	}
	work, stop := context.WithDeadline(ctx, until.Add(-time.Second))
	defer stop()
	var first error
	for _, id := range ids {
		if work.Err() != nil {
			break
		}
		attempted++
		if err := advance(work, id); err != nil && first == nil {
			first = err
		}
	}
	if first == nil {
		first = work.Err()
	}
	return attempted, first
}

func (d *CaptureCleanupWorkerDeployment) releaseProviderHistoryPage(ctx context.Context, keys []value.OperationHistoryKey) (attempted int, err error, current bool) {
	step := "history-input"
	defer func() {
		if err != nil {
			var stopped *cleanupRuntimeError
			if !errors.As(err, &stopped) {
				err = &cleanupRuntimeError{step, err}
			}
		}
	}()
	// This is a historical scheduling key, not retained effect authority.
	// Keep all original fields, including DeleteBy, unchanged through the queue.
	// SQL must still be able to report and drain overdue history under a newly
	// acquired current native/recovery operation; expiry never refunds spend.
	if !validCleanupHistoryPage(keys) || d.history.Finalizer == nil {
		return 0, mounts.ErrUnavailable, false
	}
	if len(keys) == 0 {
		return 0, nil, true
	}
	step = "history-projection-begin"
	op, lease, err := d.beginProviderCleanup(ctx)
	if err != nil {
		return 0, err, false
	}
	defer lease.Release()
	defer op.Close()
	step = "history-release"
	attempted, err = releaseCleanupHistoryPage(op.Context(), op.FreshUntil(), keys, d.history.Finalizer)
	if final := op.Finish(op.Context()); final != nil {
		return attempted, &cleanupRuntimeError{"history-projection-finish", final}, false
	}
	return attempted, err, true
}

// All keys are checked before entering native admission. An expired historical
// DeleteBy remains a valid drain input; SQL independently keeps overdue spend.
func validCleanupHistoryPage(keys []value.OperationHistoryKey) bool {
	if len(keys) > 16 {
		return false
	}
	for _, key := range keys {
		if !key.Valid() {
			return false
		}
	}
	return true
}

// The existing page shares one original native bracket, not SQL effect authority.
// Each exact key keeps its independent recovery/lock/incarnation transaction.
// Reserve the original final second for Finish; never replace an original end.
func releaseCleanupHistoryPage(ctx context.Context, until time.Time, keys []value.OperationHistoryKey, finalizer auditapp.OperationHistoryFinalizer) (attempted int, err error) {
	if ctx == nil || finalizer == nil || until.IsZero() || !validCleanupHistoryPage(keys) {
		return 0, mounts.ErrUnavailable
	}
	if outer, ok := ctx.Deadline(); ok && outer.Before(until) {
		until = outer
	}
	work, stop := context.WithDeadline(ctx, until.Add(-time.Second))
	defer stop()
	var first error
	for _, key := range keys {
		if work.Err() != nil {
			break
		}
		attempted++
		_, err := finalizer.ReleaseOperationHistory(work, key)
		if first == nil && err != nil {
			first = err
		}
	}
	if first == nil {
		first = work.Err()
	}
	return attempted, first
}

// Cleanup failures remain pending and charged. Diagnostics carry only local
// closed stage names and existing error classes, never row or provider text.
type cleanupRuntimeError struct {
	step  string
	cause error
}

func (e *cleanupRuntimeError) Error() string     { return "operation cleanup: " + e.step }
func (e *cleanupRuntimeError) Unwrap() error     { return e.cause }
func (e *cleanupRuntimeError) FixedStep() string { return e.step }
func cleanupRuntimeEvent(err error) string {
	if err == nil {
		return "effect/ok"
	}
	var stopped *cleanupRuntimeError
	if errors.As(err, &stopped) {
		step := stopped.step
		if inner := auditapp.OperationCleanupFailureStep(stopped.cause); inner != "" {
			step += "/" + inner
		}
		return step + "/" + errorClass(err)
	}
	return "effect/" + errorClass(err)
}
