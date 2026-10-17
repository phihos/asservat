package evidence

import (
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// DownloadWorkerPending is a positive observation of the original acknowledged
// Job and its bounded zero-or-one pending Pod set. It is never synthesized from
// an unknown create reply, absent Job, API error or changed execution inputs.
// It permits only later fresh-current continuation of the same worker intent.
type DownloadWorkerPending struct {
	Intent                 authorization.DownloadWorkerIntent
	Job                    authorization.DownloadWorkerJob
	ObservedAt, ValidUntil time.Time
}

func (p *DownloadWorkerPending) Error() string { return "download worker startup pending" }
func (p *DownloadWorkerPending) Valid(now time.Time) bool {
	return p != nil && p.Job.Valid(p.Intent) && identity.Fresh(p.ObservedAt, p.ValidUntil, now, 5*time.Second) && !p.ValidUntil.After(p.Intent.RunUntil)
}
