package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auth "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NativeKeyAuthority selects between the two immutable prepaid key identities:
// the original metadata batch and a separate response window. This is a closed
// purpose-specific union, never try-one-then-fallback after denial/unknown spend.
// Both delegates use the same scoped key-service credential and their existing
// independent current SQL/effect checks before irreversible slot consumption.
type NativeKeyAuthority struct {
	preparation *DownloadKeys
	window      *NativeKeys
	projection  *ProjectionKeys
}

func NewNativeKeyAuthority(ctx context.Context, pool *pgxpool.Pool, root string, profile value.DownloadWorkerProfile, scope value.KeyScope, guards DownloadTransactionGuards) (*NativeKeyAuthority, error) {
	preparation, e := NewDownloadKeys(ctx, pool, root, scope, guards)
	if e != nil {
		return nil, e
	}
	window, e := NewNativeKeys(ctx, pool, root, profile, scope, guards)
	if e != nil {
		return nil, e
	}
	return &NativeKeyAuthority{preparation: preparation, window: window}, nil
}

// WithProjectionKeys binds the one additional closed purpose at startup. The
// independent key-service credential never gains query admission/worker writes.
func (s *NativeKeyAuthority) WithProjectionKeys(projection *ProjectionKeys) error {
	if s == nil || s.projection != nil || projection == nil || projection.scope != s.preparation.scope || projection.queries.root != s.preparation.downloads.root {
		return auth.ErrKeyDenied
	}
	s.projection = projection
	return nil
}
func (s *NativeKeyAuthority) Resolve(ctx context.Context, peer value.KeyPeer, r value.KeyRequestInfo) (value.KeyOperationPermit, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !value.UUID(r.AuthorityID) || r.Scope != s.preparation.scope || r.Operation != "unwrap" || r.RequestDigest == (artifact.Digest{}) {
		return value.KeyOperationPermit{}, auth.ErrKeyDenied
	}
	root := s.preparation.downloads.root
	q := custodydb.New(s.preparation.downloads.ledger.pool)
	_, first := q.ReadDownloadKeyBinding(ctx, custodydb.ReadDownloadKeyBindingParams{BatchID: id(r.AuthorityID), RootID: id(root)})
	_, second := q.ReadNativeKey(ctx, custodydb.ReadNativeKeyParams{WindowID: id(r.AuthorityID), RootID: id(root)})
	third := error(pgx.ErrNoRows)
	if s.projection != nil {
		_, third = q.ReadProjectionKeyBinding(ctx, id(r.AuthorityID))
	}
	// Timeouts, permission errors, corrupt/ambiguous presence and missing rows are
	// unavailable. Never send a failed/depleted preparation to the window writer.
	count := 0
	for _, err := range []error{first, second, third} {
		if err == nil {
			count++
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return value.KeyOperationPermit{}, auth.ErrKeyDenied
		}
	}
	if ctx.Err() != nil || count != 1 {
		return value.KeyOperationPermit{}, auth.ErrKeyDenied
	}
	if first == nil {
		return s.preparation.Resolve(ctx, peer, r)
	}
	if third == nil {
		return s.projection.Resolve(ctx, peer, r)
	}
	return s.window.Resolve(ctx, peer, r)
}
