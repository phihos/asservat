package authorization

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

const CapacitySessionBackingFormat = "protected-capacity/v1"
const CapacitySessionBackingBytes = 8 << 10

// CapacitySessionBacking is frozen by the SQL54 session-insert trigger from
// that managed allocation's Ready account and locked child backing. It is not a
// caller-provided configuration, operation permit or recovery observation.
// Existing sessions never acquire one during a parent configuration renewal.
type CapacitySessionBacking struct {
	Format                             string
	AccountID, AttemptID, AllocationID string
	Revision                           int64
	PoolSource, PolicySource           identity.Revision
	AllocationUntil, ControlUntil      time.Time
	AuditStoreID                       string
	AuditWriteUntil                    time.Time
	Native                             NativeBacking
}

func (b CapacitySessionBacking) Valid() bool {
	if b.Format != CapacitySessionBackingFormat || !UUID(b.AccountID) || !UUID(b.AttemptID) || !UUID(b.AllocationID) || b.Revision < 1 || b.Revision > 1<<60 || !b.PoolSource.Valid() || !b.PolicySource.Valid() || !UUID(b.AuditStoreID) || !b.Native.Valid() || b.Native.AllocationID != b.AllocationID {
		return false
	}
	for _, d := range []time.Time{b.AllocationUntil, b.ControlUntil, b.AuditWriteUntil, b.Native.ValidUntil, b.Native.RetireBy} {
		if d.IsZero() || d.Nanosecond()%1000 != 0 {
			return false
		}
	}
	return !b.AuditWriteUntil.Before(b.ControlUntil) && !b.AuditWriteUntil.After(b.ControlUntil.Add(5*time.Minute))
}

// This checks exact historical configuration identity and original session
// dates, not present-day authority. Positive cleanup may read it after expiry;
// current admission, session state, permission and recovery remain separate.
func (b CapacitySessionBacking) Matches(s artifact.DownloadSession) bool {
	return b.Valid() && s.Valid() && b.AllocationID == s.AllocationID && b.Native.RootID == s.Scope.RootID && !s.Deadline.After(b.AllocationUntil) && !s.Deadline.After(b.ControlUntil) && !s.Deadline.After(b.Native.ValidUntil)
}
