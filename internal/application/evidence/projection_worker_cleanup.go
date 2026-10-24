package evidence

import (
	"context"
	"sync/atomic"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	value "asservat.local/asservat/internal/domain/authorization"
)

// Query cleanup observes only expired admitted workers. It does not read evidence or
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

// Native download workers share the acquisition slots and may end before
// RunUntil. Bound rows are retired only after positive termination evidence.
type DownloadCleanupCandidate struct {
	Worker      value.DownloadWorker
	Termination value.DownloadWorkerTermination
}
type DownloadCleanupLedger interface {
	UnretiredDownloadWorkers(context.Context) ([]DownloadCleanupCandidate, error)
	ConfirmDownloadWorkerTermination(context.Context, value.DownloadWorkerTermination) (value.DownloadWorkerTermination, error)
	RetireDownloadWorker(context.Context, value.DownloadWorkerRetirement) error
}
type DownloadCleanupJobs interface {
	ObserveDownloadWorkerTermination(context.Context, value.DownloadWorker) (value.DownloadWorkerTermination, error)
	RetireDownloadWorker(context.Context, value.DownloadWorkerTermination) (value.DownloadWorkerRetirement, error)
}

// ProjectionWorkerCleanup retires both shared acquisition worker kinds: query
// workers after RunUntil and native download workers once they have ended.
type ProjectionWorkerCleanup struct {
	Ledger       ProjectionCleanupLedger
	Jobs         ProjectionCleanupJobs
	Downloads    DownloadCleanupLedger
	DownloadJobs DownloadCleanupJobs
	Now          func() time.Time
	Report       func(string)
	next         atomic.Uint64
}

func (s *ProjectionWorkerCleanup) failed(stage string) {
	if s.Report != nil {
		s.Report(stage)
	}
}

// CleanupProjectionWorkers makes at most one physical cleanup attempt per
// demand, within that demand's unchanged context. The bounded, rotating list
// prevents one uncertain Job from monopolizing later cleanup opportunities.
// Unknown state remains charged; it is never converted into absence or success.
func (s *ProjectionWorkerCleanup) CleanupProjectionWorkers(ctx context.Context) {
	if s == nil || s.Ledger == nil || s.Jobs == nil || s.Now == nil || ctx == nil || ctx.Err() != nil {
		return
	}
	failed := s.failed
	rows, err := s.Ledger.ExpiredProjectionWorkers(ctx)
	if err != nil || len(rows) > 16 || ctx.Err() != nil {
		failed("selection")
		return
	}
	var downloads []DownloadCleanupCandidate
	if s.Downloads != nil && s.DownloadJobs != nil {
		// A download listing failure leaves those rows charged; query cleanup continues.
		if downloads, err = s.Downloads.UnretiredDownloadWorkers(ctx); err != nil || len(downloads) > 16 || ctx.Err() != nil {
			failed("download-selection")
			downloads = nil
		}
	}
	n := uint64(len(rows) + len(downloads))
	if n == 0 || ctx.Err() != nil {
		return
	}
	k := int((s.next.Add(1) - 1) % n)
	if k >= len(rows) {
		s.retireDownload(ctx, downloads[k-len(rows)])
		return
	}
	c := rows[k]
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

// retireDownload follows the query order: persisted termination before the
// UID-preconditioned delete, then the retirement record that frees the slot.
// A running worker yields no evidence and simply stays charged.
func (s *ProjectionWorkerCleanup) retireDownload(ctx context.Context, c DownloadCleanupCandidate) {
	w, t := c.Worker, c.Termination
	if !w.Valid() {
		return
	}
	if !t.Valid(t.ObservedAt) {
		observed, err := s.DownloadJobs.ObserveDownloadWorkerTermination(ctx, w)
		if err != nil || !observed.Valid(s.Now()) || observed.Worker != w || ctx.Err() != nil {
			if !s.Now().Before(w.Intent.RunUntil) {
				s.failed("download-termination-read")
			}
			return
		}
		t, err = s.Downloads.ConfirmDownloadWorkerTermination(ctx, observed)
		if err != nil || !t.Valid(t.ObservedAt) || t.Worker != w || ctx.Err() != nil {
			s.failed("download-termination-record")
			return
		}
	}
	retired, err := s.DownloadJobs.RetireDownloadWorker(ctx, t)
	if err != nil || !retired.Valid(s.Now()) || retired.Termination != t || ctx.Err() != nil {
		s.failed("download-delete-proof")
		return
	}
	if err := s.Downloads.RetireDownloadWorker(ctx, retired); err != nil {
		s.failed("download-retirement-record")
	}
}
