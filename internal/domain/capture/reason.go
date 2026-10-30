package capture

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// CaptureReasonMetadata is private already-authorized metadata, not a permit.
// AuditCaptureID identifies an actual audit record after all parent members were
// authorized; CaptureID is the genuine public parent or singleton binding.
type CaptureReasonMetadata struct {
	RootID, CaptureID, AuditCaptureID string
	Reference                         ProtectedReasonRef
	Requester                         identity.Principal
	ScopeDigest                       artifact.Digest
}

func (r CaptureReasonMetadata) Valid() bool {
	return authorization.UUID(r.RootID) && authorization.UUID(r.CaptureID) && authorization.UUID(r.AuditCaptureID) && r.Reference.Valid() && r.Requester.Valid() && r.ScopeDigest != (artifact.Digest{})
}
