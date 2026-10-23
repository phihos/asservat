package evidence

import (
	"context"
	"sync/atomic"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	value "asservat.local/asservat/internal/domain/authorization"
)

// Cleanup observes only expired admitted workers. It does not read evidence or
// refund query history, and does not need the admitting human to return.
type ProjectionCleanupCandidate struct {
	State       ProjectionWorkerState
	Termination value.AcquisitionWorkerTermination
}
type ProjectionCleanupLedger interface {
	ExpiredProjectionWorkers(context.Context) ([]ProjectionCleanupCandidate, error)
	AbandonUnclaimedProjectionWorker(context.Context, query.ContextProjectionWorkerIntent) error
	ConfirmProjectionTermination(context.Context, value.AcquisitionWorkerTermination) (value.AcquisitionWorkerTermination, error)
	RetireProjectionWorker(context.Context, value.AcquisitionWorkerRetirement) error
}
type ProjectionCleanupJobs interface {
	ObserveExpiredProjectionWorker(context.Context, value.AcquisitionWorkerIntent, value.DownloadWorkerJob, value.AcquisitionWorker) (value.AcquisitionWorkerTermination, error)
	RetireAcquisitionWorker(context.Context, value.AcquisitionWorkerTermination) (value.AcquisitionWorkerRetirement, error)
}

type ProjectionWorkerCleanup struct {
	Ledger ProjectionCleanupLedger
	Jobs   ProjectionCleanupJobs
	Now    func() time.Time
	Report func(string)
	next   atomic.Uint64
}

// CleanupProjectionWorkers makes at most one physical cleanup attempt per
// demand, within that demand's unchanged context. The bounded, rotating list
// prevents one uncertain Job from monopolizing later cleanup opportunities.
// Unknown state remains charged; it is never converted into absence or success.
func (s *ProjectionWorkerCleanup) CleanupProjectionWorkers(ctx context.Context) {
	if s == nil || s.Ledger == nil || s.Jobs == nil || s.Now == nil || ctx == nil || ctx.Err() != nil {
		return
	}
	failed := func(stage string) {
		if s.Report != nil {
			s.Report(stage)
		}
	}
	rows, err := s.Ledger.ExpiredProjectionWorkers(ctx)
	if err != nil || len(rows) > 16 || ctx.Err() != nil {
		failed("selection")
		return
	}
	if len(rows) == 0 {
		return
	}
	c := rows[(s.next.Add(1)-1)%uint64(len(rows))]
	i := c.State.Intent.Worker
	if !c.State.Intent.Valid() || s.Now().Before(i.RunUntil) {
		return
	}
	if !c.State.Claimed {
		// The SQL lock proves no create permission was ever issued and prevents
		// a concurrent claim. No Kubernetes absence or expiry proof is invented.
		if err := s.Ledger.AbandonUnclaimedProjectionWorker(ctx, c.State.Intent); err != nil {
			failed("unclaimed")
		}
		return
	}
	termination := c.Termination
	if !termination.Valid(termination.ObservedAt) {
		termination, err = s.Jobs.ObserveExpiredProjectionWorker(ctx, i, c.State.Job, c.State.Worker)
		if err != nil || !termination.Valid(s.Now()) || termination.Worker.Intent != i || ctx.Err() != nil {
			failed("termination-read")
			return
		}
		termination, err = s.Ledger.ConfirmProjectionTermination(ctx, termination)
		if err != nil || !termination.Valid(termination.ObservedAt) || termination.Worker.Intent != i || ctx.Err() != nil {
			failed("termination-record")
			return
		}
	}
	retired, err := s.Jobs.RetireAcquisitionWorker(ctx, termination)
	if err != nil || !retired.Valid(s.Now()) || retired.Termination != termination || ctx.Err() != nil {
		failed("delete-proof")
		return
	}
	if err := s.Ledger.RetireProjectionWorker(ctx, retired); err != nil {
		failed("retirement-record")
	}
}
