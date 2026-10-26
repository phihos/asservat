package sharing

import (
	"context"

	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// Request is a share prepared by Service after every current check.
// The store derives the case route and target from the published locator and
// rejects a mismatch; it never trusts these fields alone.
type Request struct {
	Share          authorization.Share
	IdempotencyKey string
	RequestDigest  artifact.Digest
}

// Revocation revokes one share of its creator (increment 1: creator only).
type Revocation struct {
	ShareID          string
	Creator          identity.Principal
	ExpectedRevision int64
	IdempotencyKey   string
}

// Store is the SQL share ledger. Create and revoke run under the current
// recovery fence; a replayed key returns the original row and replay=true.
type Store interface {
	authapp.ShareReader
	CreateShare(context.Context, Request, artifact.RecoveryProof) (authorization.Share, bool, error)
	OwnedShares(ctx context.Context, creator identity.Principal, limit int) ([]authorization.Share, error)
	ReceivedShares(ctx context.Context, caller identity.Identity, limit int) ([]authorization.Share, error)
	RevokeShare(context.Context, Revocation, artifact.RecoveryProof) (authorization.Share, bool, error)
}
