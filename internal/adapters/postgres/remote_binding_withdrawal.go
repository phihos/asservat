package postgres

import (
	"context"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgtype"
)

// WithdrawUnregistered forgets withdrawn clusters before this federation
// revision accepts connections. Concurrent starts with the same registrations
// change the stream only once, when a delivery is actually removed.
func (s *RemoteAccessBindings) WithdrawUnregistered(ctx context.Context, active []string) error {
	ids := make([]pgtype.UUID, 0, len(active))
	for _, cluster := range active {
		if !authorization.UUID(cluster) {
			return cfg.ErrInvalid
		}
		ids = append(ids, id(cluster))
	}
	return permissionError(s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		return q.WithdrawRemoteBindings(ctx, custodydb.WithdrawRemoteBindingsParams{RootID: id(s.root), ActiveClusters: ids})
	}))
}
