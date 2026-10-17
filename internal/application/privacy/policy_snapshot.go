package privacy

import (
	"context"

	value "asservat.local/asservat/internal/domain/privacy"
)

// PolicySnapshotReader observes one fixed enrolled control namespace. Successful
// reads are not retention authority until source/selector guards and complete
// hub/local topology have been established by the coordinating policy reader.
type PolicySnapshotReader interface {
	RetentionSnapshot(context.Context) (value.PolicySnapshot, error)
}

// SourceProtection proves current API write enforcement for one pinned source.
// It does not accept preexisting values, protect workload selector labels, or
// establish that the complete configured hub/local topology has been supplied.
type SourceProtection = value.SourceProtection
type PolicyProtectionReader interface {
	RetentionProtection(context.Context) (SourceProtection, error)
}
