package evidence

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"time"
)

// These ports expose the existing worker lifecycle under real query authority.
// Polling receives Read/Bind only; it cannot reserve or claim a second worker.
type ProjectionWorkerState struct {
	Intent           query.ContextProjectionWorkerIntent
	Receipt          audit.Receipt
	Audited, Claimed bool
	Job              value.DownloadWorkerJob
	Worker           value.AcquisitionWorker
}
type ProjectionWorkerLedger interface {
	ReserveProjectionWorker(context.Context, query.ContextQuery, query.ContextQueryRequest, query.ContextProjectionAuthority) (ProjectionWorkerState, error)
	ReadProjectionWorker(context.Context, query.ContextQuery, query.ContextQueryRequest, query.ContextProjectionAuthority) (ProjectionWorkerState, error)
	ClaimProjectionWorker(context.Context, query.ContextProjectionWorkerIntent, query.ContextQueryRequest, query.ContextProjectionAuthority, audit.Receipt) (value.AcquisitionWorkerLaunch, error)
	RecordProjectionWorkerJob(context.Context, query.ContextProjectionWorkerIntent, value.DownloadWorkerJob, query.ContextQueryRequest, query.ContextProjectionAuthority) error
	BindProjectionWorker(context.Context, query.ContextProjectionWorkerIntent, value.AcquisitionWorker, query.ContextQueryRequest, query.ContextProjectionAuthority) error
}
type AcquisitionWorkerJobs interface {
	CreateAcquisitionWorker(context.Context, value.AcquisitionWorkerLaunch) (value.DownloadWorkerJob, error)
	FindAcquisitionWorkerJob(context.Context, value.AcquisitionWorkerIntent) (value.DownloadWorkerJob, error)
	ObserveAcquisitionWorker(context.Context, value.AcquisitionWorkerIntent, value.DownloadWorkerJob) (value.AcquisitionWorker, error)
	ObserveAcquisitionWorkerTermination(context.Context, value.AcquisitionWorker) (value.AcquisitionWorkerTermination, error)
	RetireAcquisitionWorker(context.Context, value.AcquisitionWorkerTermination) (value.AcquisitionWorkerRetirement, error)
}

type ProjectionWorkerAdmission struct {
	Ledger  ProjectionWorkerLedger
	Jobs    AcquisitionWorkerJobs
	Audit   auditapp.ProjectionWorkerWriter
	Now     func() time.Time
	Cleanup *ProjectionWorkerCleanup
}

func (s *ProjectionWorkerAdmission) AdmitProjectionWorker(ctx context.Context, q query.ContextQuery, owner ContextProjectionRequestOwner) error {
	if s == nil || s.Ledger == nil || s.Jobs == nil || s.Audit == nil || s.Now == nil || ctx == nil || owner == nil {
		return query.ErrUnavailable
	}
	if s.Cleanup != nil {
		s.Cleanup.CleanupProjectionWorkers(ctx)
	}
	a, e := owner.CheckCurrent(ctx)
	if e != nil || !q.Current(a, s.Now()) || ctx.Err() != nil {
		return collapsed("current", query.ErrUnavailable, e)
	}
	r := owner.Request()
	call, stop := context.WithDeadline(ctx, a.ValidUntil)
	defer stop()
	current := func() bool { return call.Err() == nil && q.Current(a, s.Now()) && r.Valid(s.Now()) }
	state, e := s.Ledger.ReserveProjectionWorker(call, q, r, a)
	if e != nil || !state.Intent.Valid() || !state.Intent.Query.Equal(q) || !current() {
		return collapsed("reserve", query.ErrUnavailable, e)
	}
	receipt := state.Receipt
	if !state.Audited {
		receipt, e = s.Audit.WriteProjectionWorkerIntent(call, state.Intent)
		if e != nil {
			return collapsed("audit", query.ErrUnavailable, e)
		}
		if !receipt.ValidProjectionWorker(state.Intent) {
			return collapsed("audit-receipt", query.ErrUnavailable, nil)
		}
		if !current() {
			return collapsed("audit-current", query.ErrUnavailable, nil)
		}
	} else if !receipt.ValidProjectionWorker(state.Intent) {
		return collapsed("audit-replay", query.ErrUnavailable, nil)
	}
	launch, e := s.Ledger.ClaimProjectionWorker(call, state.Intent, r, a, receipt)
	if e != nil || !launch.Valid(s.Now()) || launch.Intent != state.Intent.Worker || !current() {
		return collapsed("claim", query.ErrUnavailable, e)
	}
	// Initial admission is the only holder of Create. An uncertain claim cannot
	// be repeated; an acknowledged replay allows exact lookup only.
	var job value.DownloadWorkerJob
	if launch.MayCreate {
		create, end := context.WithDeadline(call, launch.Until)
		job, e = s.Jobs.CreateAcquisitionWorker(create, launch)
		end()
	} else {
		job, e = s.Jobs.FindAcquisitionWorkerJob(call, launch.Intent)
	}
	if e != nil || !job.ValidAcquisition(launch.Intent) || !current() {
		return collapsed("job", query.ErrUnavailable, e)
	}
	if e = s.Ledger.RecordProjectionWorkerJob(call, state.Intent, job, r, a); e != nil || !current() {
		return collapsed("job-record", query.ErrUnavailable, e)
	}
	return nil
}
