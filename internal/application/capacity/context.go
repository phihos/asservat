package capacity

import (
	"context"

	"asservat.local/asservat/internal/domain/capture"
)

// ContextStorageBindings is a protected configuration-reconciliation facet,
// never a user operation for selecting cheaper or less restricted storage.
type ContextStorageBindings interface {
	BindContextStorage(context.Context, capture.StorageBinding) error
}
