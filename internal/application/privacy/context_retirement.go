package privacy

import (
	"context"
	"time"
)

// ContextRetirementDependencies is a point-in-time diagnostic for C15 cleanup.
// It is not a permit, a lock, or proof of quiescence. Even when all stored
// blockers are absent, independently acknowledged writer/deletion/restore
// checkpoints and a finite metadata policy must precede compaction or release.
// This component cannot issue that proof and provides no retirement mutation.
type ContextRetirementDependencies struct {
	ObservedAt                                                         time.Time
	CustodyDeleted                                                     bool
	IntentAuditPending, VerificationAuditPending                       bool
	ExecutionUnresolved, RetainedCopyReceipts                          bool
	DownloadDependents, RetentionAuditPending, RetentionCatchupPending bool
}

type ContextRetirementReader interface {
	ContextRetirementDependencies(context.Context, string) (ContextRetirementDependencies, error)
}
