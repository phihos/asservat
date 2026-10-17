package privacy

import (
	"asservat.local/asservat/internal/domain/artifact"
	"time"
)

// SourceProtection is a current observation of write enforcement, not initial
// value acceptance, selector trust, topology completeness or source readiness.
type SourceProtection struct {
	SourceClusterID, ControlNamespaceUID string
	Digest                               artifact.Digest
	ObservedAt, FreshUntil               time.Time
}
