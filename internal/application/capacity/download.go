package capacity

import (
	"asservat.local/asservat/internal/domain/artifact"
	"context"
)

// A protected configuration facet. Allocations are immutable, independently
// reserved for one workload, finite and disjoint from incident storage/upload.
type DownloadAllocations interface {
	BindDownloadAllocation(context.Context, artifact.DownloadAllocation) error
}
