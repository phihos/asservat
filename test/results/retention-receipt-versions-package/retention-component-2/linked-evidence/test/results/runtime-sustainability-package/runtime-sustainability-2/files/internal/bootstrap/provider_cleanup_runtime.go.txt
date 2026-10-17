package bootstrap

import (
	"context"
	"reflect"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/audit"
)

// Scheduling queries carry no native/effect authority and do not acquire a
// FIFO ticket. Each selected row is independently checked by its actual SQL
// transaction after admission; the page is never a retained permit.
func (d *CaptureCleanupWorkerDeployment) runProviderCleanup(ctx context.Context) error {
	cursor := ""
	for ctx.Err() == nil {
		schedule, end := context.WithTimeout(ctx, 5*time.Second)
		ids, err := d.journal.DueCaptureOperations(schedule, cursor)
		end()
		if err != nil || len(ids) > 16 {
			if err == nil {
				err = mounts.ErrUnavailable
			}
			return err
		}
		pending := false
		for _, id := range ids {
			effectErr, current := d.advanceProviderCleanup(ctx, id)
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
			return err
		}
		for _, key := range keys {
			effectErr, current := d.releaseProviderHistory(ctx, key)
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

func (d *CaptureCleanupWorkerDeployment) advanceProviderCleanup(ctx context.Context, id string) (error, bool) {
	op, lease, err := d.beginProviderCleanup(ctx)
	if err != nil {
		return err, false
	}
	defer lease.Release()
	defer op.Close()
	call := op.Context()
	state, err := d.journal.ReadOperationLifecycle(call, id)
	if err == nil {
		b := state.Intent.Lifecycle
		switch {
		case state.TerminalAcknowledged:
			err = d.finalizer.RetireOperationAudit(call, id)
		case b != nil && b.Policy.OverdueTerminal == value.OperationOverdueTerminal && !state.CertificateStarted && state.CertificateWriter == nil && state.CertificateReceipt == nil && !time.Now().Before(b.CertificatePurgeAt.Add(-time.Duration(b.Policy.ProofWindowSeconds)*time.Second)):
			err = d.overdue.Advance(call, id)
		default:
			err = d.healthy.Advance(call, id)
		}
	}
	if final := op.Finish(call); final != nil {
		return final, false
	}
	// A failed/unknown effect remains pending and charged. Only the existing SQL
	// lifecycle decides what a later independently admitted invocation may do.
	return err, true
}

func (d *CaptureCleanupWorkerDeployment) releaseProviderHistory(ctx context.Context, key value.OperationHistoryKey) (error, bool) {
	// This is a historical scheduling key, not retained effect authority.
	// Keep all original fields, including DeleteBy, unchanged through the queue.
	// SQL must still be able to report and drain overdue history under a newly
	// acquired current native/recovery operation; expiry never refunds spend.
	if !key.Valid() {
		return mounts.ErrUnavailable, false
	}
	op, lease, err := d.beginProviderCleanup(ctx)
	if err != nil {
		return err, false
	}
	defer lease.Release()
	defer op.Close()
	_, err = d.finalizer.ReleaseOperationHistory(op.Context(), key)
	if final := op.Finish(op.Context()); final != nil {
		return final, false
	}
	return err, true
}
