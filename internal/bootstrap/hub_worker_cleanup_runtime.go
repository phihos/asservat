package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
)

// cleanupWorkWindow bounds one admitted group or history page. It is a
// scheduling bound, not authority: each row's SQL transaction checks recovery,
// locks and its own original deadlines.
const cleanupWorkWindow = 5 * time.Second

// hubWorkerCleanupDeployment owns the three cleanup pools (journal, verifier,
// finalizer), the cleanup provider keys and the two object-store principals.
type hubWorkerCleanupDeployment struct {
	admission                    *fleetapp.WorkerRuntimeAdmission
	providers                    *kms.InstalledConfigurationProviderEffects
	closers                      []func()
	journal, verifier, finalizer *postgres.OperationLifecycles
	healthy                      auditapp.OperationCleanup
	overdue                      auditapp.OperationOverdueCleanup
	history                      auditapp.OperationHistoryCleanup
}

func (d *hubWorkerCleanupDeployment) close() {
	if d == nil {
		return
	}
	for i := len(d.closers) - 1; i >= 0; i-- {
		d.closers[i]()
	}
	d.closers = nil
}

// run sweeps due lifecycles and history once per second. Scheduling queries
// carry no effect authority; each selected row is checked by its own SQL
// transaction. Failed or unknown effects stay pending and charged. Only
// cancellation or an invalid scheduling result ends the loop.
func (d *hubWorkerCleanupDeployment) run(ctx context.Context) error {
	cursor := ""
	report := eventLog(os.Stderr, "operation cleanup")
	report("started")
	for ctx.Err() == nil {
		operationsStarted := time.Now()
		schedule, end := context.WithTimeout(ctx, 5*time.Second)
		ids, err := d.journal.DueWorkerOperations(schedule, cursor)
		end()
		if err != nil || len(ids) > 16 {
			// A transient SQL failure is retried at the next sweep.
			report(cleanupRuntimeEvent(&cleanupRuntimeError{"due-lifecycles", errOr(err)}))
			ids = nil
		} else if len(ids) == 0 {
			report("due-lifecycles/empty")
		}
		operationsAttempted := 0
		for operationsAttempted < len(ids) {
			group := ids[operationsAttempted:min(operationsAttempted+2, len(ids))]
			attempted, effectErr := d.advanceGroup(ctx, group, report)
			operationsAttempted += attempted
			if attempted < len(group) {
				report(cleanupRuntimeEvent(effectErr))
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
			report(cleanupRuntimeEvent(&cleanupRuntimeError{"due-history", errOr(err)}))
			keys = nil
		}
		historyAttempted := 0
		if len(keys) > 0 {
			var effectErr error
			historyAttempted, effectErr = d.releaseHistoryPage(ctx, keys)
			report(cleanupRuntimeEvent(effectErr))
		}
		// One numeric aggregate per nonempty sweep. IDs, error text and
		// provider inputs never enter these diagnostics.
		if len(ids)+len(keys) > 0 {
			fmt.Fprintf(os.Stderr, "operation cleanup: sweep operations_selected=%d operations_attempted=%d operations_ms=%d history_selected=%d history_attempted=%d history_ms=%d\n", len(ids), operationsAttempted, operationsElapsed.Milliseconds(), len(keys), historyAttempted, time.Since(historyStarted).Milliseconds())
		}
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

func errOr(err error) error {
	if err == nil {
		return mounts.ErrUnavailable
	}
	return err
}

// advanceGroup refreshes the cleanup credentials, takes one admission ticket
// and advances at most two exact lifecycle IDs within cleanupWorkWindow.
func (d *hubWorkerCleanupDeployment) advanceGroup(ctx context.Context, ids []string, report func(string)) (attempted int, err error) {
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
		return 0, mounts.ErrUnavailable
	}
	step = "provider-refresh"
	if d.providers == nil {
		return 0, mounts.ErrUnavailable
	}
	// Credential maintenance precedes admission and never extends its
	// context or caches object-store/crypto effect authority.
	if err := d.providers.RefreshCleanup(ctx); err != nil {
		return 0, err
	}
	step = "admission"
	lease, err := d.admission.WaitCleanup(ctx)
	if err != nil {
		return 0, err
	}
	defer lease.Release()
	step = "lifecycle-group-work"
	return advanceCleanupLifecycleGroup(lease.Context(), time.Now().Add(cleanupWorkWindow), ids, func(call context.Context, id string) error {
		effectErr := d.advanceOperation(call, id)
		if report != nil {
			report(cleanupRuntimeEvent(effectErr))
		}
		return effectErr
	})
}

func (d *hubWorkerCleanupDeployment) advanceOperation(ctx context.Context, id string) (err error) {
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

// advanceCleanupLifecycleGroup runs the group until the earlier of until and
// the parent deadline, and stops before attempting another ID after expiry.
func advanceCleanupLifecycleGroup(ctx context.Context, until time.Time, ids []string, advance func(context.Context, string) error) (attempted int, err error) {
	if ctx == nil || until.IsZero() || advance == nil || !validCleanupLifecycleGroup(ids) {
		return 0, mounts.ErrUnavailable
	}
	work, stop := context.WithDeadline(ctx, until)
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

func (d *hubWorkerCleanupDeployment) releaseHistoryPage(ctx context.Context, keys []value.OperationHistoryKey) (attempted int, err error) {
	step := "history-input"
	defer func() {
		if err != nil {
			var stopped *cleanupRuntimeError
			if !errors.As(err, &stopped) {
				err = &cleanupRuntimeError{step, err}
			}
		}
	}()
	// A historical scheduling key, not effect authority. All original fields,
	// including DeleteBy, pass through unchanged; expiry never refunds spend.
	if !validCleanupHistoryPage(keys) || d.history.Finalizer == nil {
		return 0, mounts.ErrUnavailable
	}
	if len(keys) == 0 {
		return 0, nil
	}
	step = "history-admission"
	lease, err := d.admission.WaitCleanup(ctx)
	if err != nil {
		return 0, err
	}
	defer lease.Release()
	step = "history-release"
	return releaseCleanupHistoryPage(lease.Context(), time.Now().Add(cleanupWorkWindow), keys, d.history.Finalizer)
}

// All keys are checked before admission. An expired historical DeleteBy
// remains a valid drain input; SQL independently keeps overdue spend.
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

// Each exact key keeps its independent recovery/lock/incarnation transaction;
// the page shares only the work window.
func releaseCleanupHistoryPage(ctx context.Context, until time.Time, keys []value.OperationHistoryKey, finalizer auditapp.OperationHistoryFinalizer) (attempted int, err error) {
	if ctx == nil || finalizer == nil || until.IsZero() || !validCleanupHistoryPage(keys) {
		return 0, mounts.ErrUnavailable
	}
	work, stop := context.WithDeadline(ctx, until)
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
