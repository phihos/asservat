package capture

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

type HistoryLimits struct{ PerSelector, PerInstallation int }

func DefaultHistoryLimits() HistoryLimits {
	return HistoryLimits{MaxHistoryPerSelector, MaxHistoryPerInstallation}
}
func (l HistoryLimits) Valid() bool {
	return l.PerSelector >= 1 && l.PerSelector <= MaxHistoryPerSelector && l.PerInstallation >= 1 && l.PerInstallation <= MaxHistoryPerInstallation
}

// Only the accepted capture and current SQL authority can bind this request.
// Supplied parameter hashes are checked against the encrypted payload before
// publication; this type itself grants neither collection nor history access.
type HistoryReservation struct {
	Expectation      HistoryExpectation
	Identity         identity.Identity
	Recovery         artifact.RecoveryProof
	Limits           HistoryLimits
	SummaryExpiresAt time.Time
	Retention        privacy.Resolution
	Source           *HistoryLineage
}
type HistoryRetention struct {
	Input        privacy.Input
	Origins      []artifact.RetentionRule
	SourceCutoff time.Time
}

func (r HistoryRetention) Valid() bool {
	return r.Input.Target.Valid() && r.Input.ControlKind == "case-metadata" && r.Input.EvidenceType == "other" && r.Input.RequestedSeconds > 0 && privacy.ValidPolicyOrigins(r.Origins)
}

type HistoryStorage struct {
	Origin                 HistoryOrigin
	Expectation            HistoryExpectation
	Copies                 artifact.Copies
	State                  string
	SummaryExpiresAt       time.Time
	ObservedAt, ValidUntil time.Time
	Target                 authorization.Target
	Retention              HistoryRetention
	Effective              privacy.Deadlines
}
type HistoryWriteRequest struct {
	Storage       HistoryStorage
	Identity      identity.Identity
	Recovery      artifact.RecoveryProof
	RequestID     string
	ExecutorEpoch string
	BundleDigest  artifact.Digest
}
type HistoryWriteResult struct {
	Authority  HistoryOperationAuthority
	Copies     artifact.Copies
	Completion HistoryWriterCompletion
	Recovery   artifact.RecoveryProof
}
type HistoryReadRequest struct {
	Retention     privacy.RetainedResolution
	Query         SettingsQuery
	RequestID     string
	ExecutorEpoch string
}
type HistoryReadPermission struct {
	Storage   HistoryStorage
	Authority HistoryOperationAuthority
}
type HistoryDeletePermission struct {
	Storage   HistoryStorage
	Authority HistoryOperationAuthority
	Writer    HistoryWriterCompletion
}
type HistoryDeleteRequest struct {
	CaptureID, RequestID, ExecutorEpoch string
	Recovery                            artifact.RecoveryProof
}

type HistoryRetirementCandidate struct{ CaptureID, ClusterID, State string }
