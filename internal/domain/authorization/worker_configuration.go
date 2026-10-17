package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// Snapshot is immutable administrator intent, with no observation timestamps,
// secrets or evidence. Protection is independently verified installation input.
type DownloadWorkerConfiguration struct {
	Profile          DownloadWorkerProfile
	RecoveryEpoch    string
	ProtectionDigest artifact.Digest
	Suspended        bool
}

func (s DownloadWorkerConfiguration) Valid() bool {
	return s.Profile.Valid() && UUID(s.RecoveryEpoch) && s.ProtectionDigest != (artifact.Digest{})
}

type DownloadWorkerObservation struct {
	Configuration          DownloadWorkerConfiguration
	ObservedAt, FreshUntil time.Time
}

func (o DownloadWorkerObservation) Valid(now time.Time) bool {
	return o.Configuration.Valid() && identity.Fresh(o.ObservedAt, o.FreshUntil, now, 5*time.Second)
}

type DownloadWorkerIdentity struct {
	Worker                 DownloadWorker
	ObservedAt, FreshUntil time.Time
}

func (o DownloadWorkerIdentity) Valid(now time.Time) bool {
	return o.Worker.Valid() && identity.Fresh(o.ObservedAt, o.FreshUntil, now, 5*time.Second) && !o.FreshUntil.After(o.Worker.Intent.RunUntil)
}
