package privacy

import (
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
)

// Each page atomically applies a single oldest outstanding source transition
// to at most 16 existing contexts, records exact lifecycle work and advances its
// durable cursor. Callers cannot supply artifact IDs or assert completion.
type RetentionCatchup interface {
	ReconcileRetentionPage(context.Context, value.PolicySourceRef, int) (value.RetentionCatchupPage, error)
}
