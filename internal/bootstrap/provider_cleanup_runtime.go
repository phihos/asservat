package bootstrap

import (
	"context"
	"errors"
	"os"
	"reflect"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	auditapp "asservat.local/asservat/internal/application/audit"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/audit"
)

// Scheduling queries carry no native/effect authority and do not acquire a
// FIFO ticket. Each selected row is independently checked by its actual SQL
// transaction after admission; the page is never a retained permit.
func (d *CaptureCleanupWorkerDeployment) runProviderCleanup(ctx context.Context) error {
	cursor := ""
	report := eventLog(os.Stderr, "operation cleanup")
	report("started")
	for ctx.Err() == nil {
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
		for _, id := range ids {
			effectErr, current := d.advanceProviderCleanup(ctx, id)
			report(cleanupRuntimeEvent(effectErr))
			if !current {
				return effectErr
			}
			pending = pending || effectErr != nil
			cursor = id
		}
		if len(ids) < 16 {
			cursor = ""
		}
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
		for _, key := range keys {
			effectErr, current := d.releaseProviderHistory(ctx, key)
			report(cleanupRuntimeEvent(effectErr))
			if !current {
				return effectErr
			}
			pending = pending || effectErr != nil
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

func (d *CaptureCleanupWorkerDeployment) advanceProviderCleanup(ctx context.Context, id string) (err error, current bool) {
	step := "provider-refresh"
	defer func() {
		if err != nil {
			var stopped *cleanupRuntimeError
			if !errors.As(err, &stopped) {
				err = &cleanupRuntimeError{step, err}
			}
		}
	}()
	if d.providers == nil {
		return mounts.ErrUnavailable, false
	}
	if err := d.providers.RefreshCleanup(ctx); err != nil {
		return err, ctx.Err() == nil
	}
	step = "projection-begin"
	op, lease, err := d.beginProviderCleanup(ctx)
	if err != nil {
		return err, false
	}
	defer lease.Release()
	defer op.Close()
	call := op.Context()
	step = "lifecycle-read"
	state, err := d.journal.ReadOperationLifecycle(call, id)
	if err == nil {
		b := state.Intent.Lifecycle
		switch {
		case state.TerminalAcknowledged:
			step = "finalize"
			err = d.finalizer.RetireOperationAudit(call, id)
		case b != nil && b.Policy.OverdueTerminal == value.OperationOverdueTerminal && !state.CertificateStarted && state.CertificateWriter == nil && state.CertificateReceipt == nil && !time.Now().Before(b.CertificatePurgeAt.Add(-time.Duration(b.Policy.ProofWindowSeconds)*time.Second)):
			step = "overdue"
			err = d.overdue.Advance(call, id)
		default:
			step = "healthy"
			err = d.healthy.Advance(call, id)
		}
	}
	if final := op.Finish(call); final != nil {
		return &cleanupRuntimeError{"projection-finish", final}, false
	}
	// A failed/unknown effect remains pending and charged. Only the existing SQL
	// lifecycle decides what a later independently admitted invocation may do.
	return err, true
}

func (d *CaptureCleanupWorkerDeployment) releaseProviderHistory(ctx context.Context, key value.OperationHistoryKey) (err error, current bool) {
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
	if !key.Valid() {
		return mounts.ErrUnavailable, false
	}
	step = "history-projection-begin"
	op, lease, err := d.beginProviderCleanup(ctx)
	if err != nil {
		return err, false
	}
	defer lease.Release()
	defer op.Close()
	step = "history-release"
	_, err = d.finalizer.ReleaseOperationHistory(op.Context(), key)
	if final := op.Finish(op.Context()); final != nil {
		return &cleanupRuntimeError{"history-projection-finish", final}, false
	}
	return err, true
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
