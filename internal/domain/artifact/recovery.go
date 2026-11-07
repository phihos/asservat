package artifact

import (
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// RecoveryProof is a finite observation of separately accepted installation
// recovery. It is runtime fencing, never part of a user's approval scope.
type RecoveryProof struct {
	InstallationID, IssuerEpoch string
	Revision                    identity.Revision
	ObservedAt, FreshUntil      time.Time
}

// Valid admits at most identity.EvidenceReadRequestWindow; producers for
// purposes other than evidence reads keep their five-second intervals.
func (p RecoveryProof) Valid(now time.Time) bool {
	return uuid(p.InstallationID) && uuid(p.IssuerEpoch) && p.Revision.Valid() && identity.Fresh(p.ObservedAt, p.FreshUntil, now, identity.EvidenceReadRequestWindow)
}
