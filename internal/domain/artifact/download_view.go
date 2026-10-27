package artifact

import (
	"fmt"
	"time"

	"asservat.local/asservat/internal/domain/identity"
)

// These are private observations, never public request fields or authority.
type DownloadRouteQuery struct {
	ArtifactID string
	Identity   identity.Identity
	Recovery   RecoveryProof
}

func (q DownloadRouteQuery) Valid(now time.Time) bool {
	return uuid(q.ArtifactID) && q.Identity.Valid(now) && q.Recovery.Valid(now)
}

type DownloadRoute struct {
	Scope                  DownloadScope
	ObservedAt, ValidUntil time.Time
}

func (r DownloadRoute) Valid(now time.Time) bool {
	return r.Scope.Valid() && identity.Fresh(r.ObservedAt, r.ValidUntil, now, DownloadLease)
}

type DownloadKeyQuery struct {
	Identity identity.Identity
	Recovery RecoveryProof
	Key      Digest
}

func (q DownloadKeyQuery) Valid(now time.Time) bool {
	return q.Identity.Valid(now) && q.Recovery.Valid(now) && q.Key != (Digest{})
}

// Found=false is only a bounded observation. Admission must check the key again
// under its existing transaction locks; a lookup failure is never absence.
type DownloadKeyLookup struct {
	Found                  bool
	Session                DownloadSession
	ObservedAt, ValidUntil time.Time
}

func (r DownloadKeyLookup) Valid(now time.Time) bool {
	return identity.Fresh(r.ObservedAt, r.ValidUntil, now, DownloadLease) && (!r.Found || r.Session.Valid())
}

// DownloadObservation is fresh authorized status, not a renewed transfer lease.
// Terminal status may outlive the original transfer deadline while current
// evidence access, retention and recovery still allow its disclosure.
type DownloadObservation struct {
	Session                DownloadSession
	ObservedAt, ValidUntil time.Time
}

func (r DownloadObservation) Valid(now time.Time) bool {
	return r.Session.Valid() && identity.Fresh(r.ObservedAt, r.ValidUntil, now, DownloadLease)
}

// Preparation names an immutable successful/audited read. Its old effect lease
// is not a current metadata disclosure lease and is never extended.
type DownloadPreparation struct {
	SessionID, BatchID string
	Generation         int64
}

func (p DownloadPreparation) Valid() bool {
	return uuid(p.SessionID) && uuid(p.BatchID) && p.Generation > 0 && p.Generation <= MaxDownloadRequests
}

// PreparedDownload is returned only by a protected regional native-work port.
// No keys or file bytes are retained. SQL independently checks its exact receipt;
// the authenticated worker channel owns the provenance of the immutable facts.
type PreparedDownload struct {
	Preparation DownloadPreparation
	Scope       DownloadScope
	Native      NativeDownloadMetadata
}

func (p PreparedDownload) Valid() bool {
	m := p.Native
	if !p.Preparation.Valid() || !p.Scope.Valid() || !ValidNativeDownloadMetadata(p.Scope.ArtifactID, m) || m.ETag != fmt.Sprintf(`"v1-%x"`, p.Scope.Version) {
		return false
	}
	// Cached dates are not authority. The coordinator overwrites both with the
	// fresh current effective limits for each response.
	return true
}

// ObservedState reports elapsed transfer lifetime without changing durable state
// or accounting. Historical terminal outcomes always retain their actual result.
func (s DownloadSession) ObservedState(now time.Time) DownloadState {
	if !s.State.Terminal() && !now.Before(s.Deadline) {
		return DownloadExpired
	}
	return s.State
}
