package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// DownloadIntent is an exact prepaid batch, not a promise of client receipt.
type DownloadIntent struct {
	SessionID string
	Batch     artifact.DownloadBatch
}

// Equal compares persisted audit identity. Location pointers and process-local
// monotonic clock readings are not persisted; exact wall-clock instants and
// every non-time field remain binding. This grants no current authority.
func (r DownloadIntent) Equal(other DownloadIntent) bool {
	normalize := func(v DownloadIntent) DownloadIntent {
		b := &v.Batch
		a := &b.Authority
		for _, at := range []*time.Time{
			&b.StartedAt, &b.LeaseUntil,
			&a.CheckedAt, &a.ValidUntil, &a.AccessUntil, &a.DeleteBy,
			&a.Retention.ObservedAt, &a.Retention.ValidUntil,
			&a.Environment.ObservedAt, &a.Environment.ValidUntil,
			&a.Environment.Processing.ObservedAt, &a.Environment.Processing.ValidUntil,
		} {
			*at = at.UTC()
		}
		return v
	}
	return normalize(r) == normalize(other)
}

func (r DownloadIntent) Valid() bool {
	b := r.Batch
	return authorization.UUID(r.SessionID) && authorization.UUID(b.ID) && b.Generation > 0 && (b.Purpose == artifact.DownloadMetadata || b.Purpose == artifact.DownloadContent) && b.Offset >= 0 && b.Offset <= artifact.MaxNativeBytes && b.OutputBytes >= 0 && b.OutputBytes <= artifact.DeliveryBytes && b.OutputBytes <= artifact.MaxNativeBytes-b.Offset && b.ReadBytes > 0 && b.ReadBytes <= artifact.MaxDownloadReadWork && !b.AuditAcknowledged && b.Authority.Valid(b.StartedAt) && b.LeaseUntil.After(b.StartedAt) && !b.LeaseUntil.After(b.Authority.ValidUntil) && (b.Purpose != artifact.DownloadMetadata || (b.Offset == 0 && b.OutputBytes == 0))
}

type DownloadOutcome struct {
	Intent            DownloadIntent
	EmittedBytes      int64
	Success, FullFile bool
	RecordedAt        time.Time
}

func (r DownloadOutcome) Equal(other DownloadOutcome) bool {
	return r.Intent.Equal(other.Intent) && r.RecordedAt.Equal(other.RecordedAt) && r.EmittedBytes == other.EmittedBytes && r.Success == other.Success && r.FullFile == other.FullFile
}

func (r DownloadOutcome) Valid() bool {
	b := r.Intent.Batch
	return r.Intent.Valid() && r.EmittedBytes >= 0 && r.EmittedBytes <= b.OutputBytes && !r.RecordedAt.Before(b.StartedAt) && (!r.Success || b.Purpose != artifact.DownloadContent || r.EmittedBytes == b.OutputBytes) && (!r.FullFile || (r.Success && b.Purpose == artifact.DownloadContent && b.Offset == 0))
}
func DownloadAuditKey(root, session, batch, phase string) string {
	return "download-audit/v1/" + root + "/" + session + "/" + batch + "/" + phase
}
func (r Receipt) ValidDownload(root, session, batch, phase string) bool {
	return r.Version != "" && r.Version != "null" && r.ValidHistoricalDownload(root, session, batch, phase)
}

// ValidHistoricalDownload parses retained receipt identity for cancellation and
// physical accounting only. It supplies no acknowledgement or current permit.
func (r Receipt) ValidHistoricalDownload(root, session, batch, phase string) bool {
	return authorization.UUID(root) && authorization.UUID(session) && authorization.UUID(batch) && (phase == "intent" || phase == "outcome") && r.Key == DownloadAuditKey(root, session, batch, phase) && (r.Version == "" || identity.Text(r.Version, 1024)) && identity.Text(r.ETag, 256) && r.Bytes > 0 && r.Bytes <= 128<<10 && r.SHA256 != (artifact.Digest{})
}
