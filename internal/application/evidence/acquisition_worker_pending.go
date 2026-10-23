package evidence

import (
	"time"

	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// AcquisitionWorkerPending is an acknowledged observation of the exact Job
// still starting. It does not authorize another create or replace missing work.
type AcquisitionWorkerPending struct {
	Intent                 value.AcquisitionWorkerIntent
	Job                    value.DownloadWorkerJob
	ObservedAt, ValidUntil time.Time
}

func (p *AcquisitionWorkerPending) Error() string { return "acquisition worker starting" }

func (p *AcquisitionWorkerPending) Valid(now time.Time) bool {
	return p != nil && p.Job.ValidAcquisition(p.Intent) && identity.Fresh(p.ObservedAt, p.ValidUntil, now, 5*time.Second) &&
		!p.ValidUntil.After(p.Intent.RunUntil)
}
