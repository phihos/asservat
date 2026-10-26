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

// Revocation revokes one share. The actor is its creator or, with Managers,
// a current manager (ADR-232 increment 4): Managers are the pinned assignment
// IDs the service found the actor holding now; the store requires each to be
// pinned by the row.
type Revocation struct {
	ShareID          string
	Actor            identity.Principal
	Managers         []string
	ExpectedRevision int64
	IdempotencyKey   string
}

// Store is the SQL share ledger. Create and revoke run under the current
// recovery fence; a replayed key returns the original row and replay=true.
// OwnedShares returns the caller's own shares and the unrevoked, unexpired
// shares pinning a management assignment of one of the caller's keys
// (candidates: the service checks current management).
type Store interface {
	authapp.ShareReader
	CreateShare(context.Context, Request, artifact.RecoveryProof) (authorization.Share, bool, error)
	Share(ctx context.Context, shareID string) (authorization.Share, error)
	OwnedShares(ctx context.Context, caller identity.Identity, limit int) ([]authorization.Share, error)
	ReceivedShares(ctx context.Context, caller identity.Identity, limit int) ([]authorization.Share, error)
	RevokeShare(context.Context, Revocation, artifact.RecoveryProof) (authorization.Share, bool, error)
}
