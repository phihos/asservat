package fleet

import (
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ObservationBasis is an original pre-native SQL read, never current fleet or
// recovery authority. Version zero records absence and permits only blocked
// initialization if that same installation is still absent at consumption.
type ObservationBasis struct {
	InstallationID         string
	Database               DatabaseIncarnation
	SemanticVersion        int64
	ObservedAt, FreshUntil time.Time
}

func (b ObservationBasis) Valid() bool {
	return authorization.UUID(b.InstallationID) && b.Database.Valid() && b.SemanticVersion >= 0 &&
		identity.Fresh(b.ObservedAt, b.FreshUntil, b.ObservedAt, 5*time.Second)
}

func (b ObservationBasis) Current(now time.Time) bool {
	return b.Valid() && identity.Fresh(b.ObservedAt, b.FreshUntil, now, 5*time.Second)
}
