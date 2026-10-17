package configuration

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
	"context"
	"time"
)

// PermissionStore is writable only by the qualified configuration reconciler.
// SQL does not become a second public configuration authoring API.
type PermissionStore interface {
	BeginPermissions(context.Context, string, string, artifact.Digest) (value.PermissionFence, error)
	RenewPermissions(context.Context, value.PermissionFence) (value.PermissionFence, error)
	AcceptPermissions(context.Context, value.PermissionBatch) (value.PermissionAcceptance, error)
	// Refresh renews only a freshly re-observed identical complete projection.
	// It does not append a new assignment or audit event for polling heartbeats.
	RefreshPermissions(context.Context, value.PermissionBatch) error
	SuspendPermissions(context.Context, value.PermissionFence) error
}

// Trust includes a verified guard/installation revision and an original finite
// deadline. It cannot be filled from a source's own review/status declarations.
type PermissionTrust struct {
	Digest                 artifact.Digest
	ObservedAt, FreshUntil time.Time
}
type PermissionTrustReader interface {
	PermissionTrust(context.Context) (PermissionTrust, error)
}
