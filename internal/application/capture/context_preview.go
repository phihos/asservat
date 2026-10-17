package capture

import (
	"context"

	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

// ContextPreviewStore persists only the finite passive blueprint. Create is
// immutable/create-only; an uncertain response never authorizes an operation.
// Enforce <=10 live previews per issuer/subject/kind across clients and <=1000
// per root atomically, with bounded expired-preview cleanup. Read requires the
// exact original actor/client and denies expiry. Neither method reserves work.
// An encrypted reason reference is opaque; never store its plaintext here.
type ContextPreviewStore interface {
	CreateContextPreview(context.Context, value.ContextPreview) error
	ReadContextPreview(context.Context, string, string, identity.Principal) (value.ContextPreview, error)
}

// ContextAdmissionReplay is a read-only transaction with current recovery and
// current SQL target permissions/denies after locks. Lookup precedes preview
// access, permitting exact accepted replay after preview or target disappearance.
// A changed digest under the same actor/client/key conflicts. Missing is the
// only result that permits a new current preview-to-admission attempt.
type ContextAdmissionReplay interface {
	LookupContextAdmission(context.Context, value.ReplayQuery) (value.Accepted, bool, error)
}
