package sharing

import (
	"context"

	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
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
// pinned by the row. Administrator marks an installation administrator's
// revocation (ADR-238): the service checked the protected fleet
// administration; revocation only restricts access.
type Revocation struct {
	ShareID          string
	Actor            identity.Principal
	Managers         []string
	Administrator    bool
	ExpectedRevision int64
	IdempotencyKey   string
}

// Transfer replaces the pinned management of one active share (ADR-238).
// Managers are the pinned assignment IDs the service found the actor holding
// now (the store requires each to be pinned by the row); Management is the
// complete new set, all held by the actor now. Creator, recipients, artifact
// and expiry never change.
type Transfer struct {
	ShareID          string
	Actor            identity.Principal
	Managers         []string
	Management       []artifact.AudienceAssignment
	ExpectedRevision int64
	IdempotencyKey   string
	RequestDigest    artifact.Digest
}

// Store is the SQL share ledger. Create, revoke and transfer run under the
// current recovery fence; a replayed key returns the original row and
// replay=true. OwnedShares returns the caller's own shares and the
// unrevoked, unexpired shares pinning a management assignment of one of the
// caller's keys (candidates: the service checks current management).
type Store interface {
	authapp.ShareReader
	CreateShare(context.Context, Request, artifact.RecoveryProof) (authorization.Share, bool, error)
	Share(ctx context.Context, shareID string) (authorization.Share, error)
	OwnedShares(ctx context.Context, caller identity.Identity, limit int) ([]authorization.Share, error)
	ReceivedShares(ctx context.Context, caller identity.Identity, limit int) ([]authorization.Share, error)
	RevokeShare(context.Context, Revocation, artifact.RecoveryProof) (authorization.Share, bool, error)
	TransferShare(context.Context, Transfer, artifact.RecoveryProof) (authorization.Share, bool, error)
}

// Administrators reads the protected fleet administration whose operators
// are the installation administrators (ADR-237, ADR-238). It grants them no
// evidence read: the share service uses it only to let them revoke.
type Administrators interface {
	FleetAdministration(context.Context) (fleet.Administration, error)
}
