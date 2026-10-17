package audit

import "time"

// Protected configuration observations, never public request fields. Configured
// account sizes mean max retained records=Accounts*RecordsPerAccount, reserving
// exactly two maximum ciphertext objects each. Accounts never recycle on age.
// Rotation of input/output MACs is independent of stable AccountVersion.
type OperationAuditPool struct {
	RootID, Lane, AccountVersion                 string
	ExpectedRevision                             int64
	Accounts, RecordsPerAccount, RetainedSeconds int64
	Paused                                       bool
	ObservedAt, FreshUntil, ValidUntil           time.Time
}
