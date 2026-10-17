package privacy

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"time"
)

// ContextDeletionCheckpoint describes a completed, positively fenced purge.
// It is immutable historical evidence, never recovery activation authority.
type ContextDeletionCheckpoint struct {
	RootID, CaptureID, StoreID, InstallationID, IssuerEpoch string
	Location                                                artifact.Location
	RegistrationDigest, WriterDigest                        artifact.Digest
	PostmasterAt                                            time.Time
	DatabaseOID                                             uint32
	PurgeFence                                              int64
	PurgedAt                                                time.Time
}

func (r ContextDeletionCheckpoint) Valid() bool {
	for _, id := range []string{r.RootID, r.CaptureID, r.StoreID, r.InstallationID, r.IssuerEpoch} {
		if !authorization.UUID(id) {
			return false
		}
	}
	return r.Location.Validate() == nil && r.RegistrationDigest != (artifact.Digest{}) && r.WriterDigest != (artifact.Digest{}) && r.DatabaseOID > 0 && r.PurgeFence > 0 && canonicalDeletionTime(r.PostmasterAt) && canonicalDeletionTime(r.PurgedAt) && !r.PurgedAt.Before(r.PostmasterAt)
}
func canonicalDeletionTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 2020 && t.Year() <= 9999 && t.Nanosecond()%1000 == 0
}
