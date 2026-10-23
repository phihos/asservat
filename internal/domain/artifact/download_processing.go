package artifact

import (
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// DownloadProcessingProof is a current result of complete durable processing
// state, not a stored permission. Effect gates compare the exact root epoch and
// sequence again under the shared root lock. No zero/missing proof is allowing.
type DownloadProcessingProof struct {
	RootID, Epoch, CaptureID string
	Location                 Location
	Sequence                 int64
	StateDigest              Digest
	ObservedAt, ValidUntil   time.Time
}

func (p DownloadProcessingProof) Valid(now time.Time) bool {
	return uuid(p.RootID) && uuid(p.Epoch) && uuid(p.CaptureID) && p.Location.Validate() == nil && p.Sequence > 0 && p.Sequence <= 1<<60 && p.StateDigest != (Digest{}) && identity.Fresh(p.ObservedAt, p.ValidUntil, now, identity.EvidenceReadRequestWindow)
}

func (p DownloadProcessingProof) Equal(q DownloadProcessingProof) bool {
	dates := p.ObservedAt.Equal(q.ObservedAt) && p.ValidUntil.Equal(q.ValidUntil)
	p.ObservedAt, q.ObservedAt = time.Time{}, time.Time{}
	p.ValidUntil, q.ValidUntil = time.Time{}, time.Time{}
	return dates && p == q
}
