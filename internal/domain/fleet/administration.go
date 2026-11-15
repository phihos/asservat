package fleet

import (
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// Administration is one observation of the installation's fleet trust row:
// its generated installation ID and issuer epoch. It assigns no rights.
type Administration struct {
	InstallationID, IssuerEpoch string
	Revision                    identity.Revision
	Suspended                   bool
	ObservedAt, FreshUntil      time.Time
}

func (a Administration) Valid(now time.Time) bool {
	return authorization.UUID(a.InstallationID) && authorization.UUID(a.IssuerEpoch) && a.Revision.Valid() && identity.Fresh(a.ObservedAt, a.FreshUntil, now, 5*time.Second)
}
