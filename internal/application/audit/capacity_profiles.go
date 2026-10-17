package audit

import (
	"context"

	value "asservat.local/asservat/internal/domain/audit"
)

// CapacityAuditProfiles reads independently accepted current backing. A
// selector consumes it once before a new Begin and retains that exact auditor
// through Finish. A failed or uncertain Begin must not select a new revision.
type CapacityAuditProfiles interface {
	ReadCapacityAuditProfiles(context.Context) (value.AcceptedCapacityAuditProfiles, error)
}
