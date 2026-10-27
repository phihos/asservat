package capture

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
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
}
type HistoryStorage struct {
	Expectation            HistoryExpectation
	Copies                 artifact.Copies
	State                  string
	SummaryExpiresAt       time.Time
	ObservedAt, ValidUntil time.Time
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
