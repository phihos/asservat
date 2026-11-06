package postgres

import (
	"context"
	"encoding/hex"
	"errors"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	live "asservat.local/asservat/internal/domain/live"
	"github.com/jackc/pgx/v5"
)

// LookupLiveWatchOwner is a protected routing locator, never a read permit.
// PrincipalKey deliberately shares the human accounting identity across clients;
// keyHex additionally binds the complete original principal/client. A watch-ID
// lookup may locate the same human's other client, but the receiving original
// Service must check its exact session actor/client before touching sources.
func (s *LiveWatches) LookupLiveWatchOwner(ctx context.Context, principalKey [32]byte, watchID, keyHex string) (fleet.OwnerBinding, bool, error) {
	var out fleet.OwnerBinding
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil || principalKey == ([32]byte{}) || (watchID == "") == (keyHex == "") {
		return out, false, live.ErrInvalid
	}
	var key []byte
	if watchID != "" {
		if !authorization.UUID(watchID) {
			return out, false, live.ErrInvalid
		}
	} else {
		var err error
		key, err = hex.DecodeString(keyHex)
		if err != nil || len(key) != 32 || hex.EncodeToString(key) != keyHex {
			return out, false, live.ErrInvalid
		}
	}
	found := false
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, err := q.LookupLiveWatchOwner(ctx, custodydb.LookupLiveWatchOwnerParams{RootID: id(s.root), PrincipalKey: principalKey[:], WatchID: id(watchID), KeyHash: key})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		out = fleet.OwnerBinding{InstallationID: uid(row.InstallationID), ClusterID: uid(row.ClusterID), IssuerEpoch: uid(row.IssuerEpoch), PodUID: uid(row.PodUid), ProcessEpoch: uid(row.ProcessEpoch)}
		if !out.Valid() || ctx.Err() != nil {
			return live.ErrUnavailable
		}
		found = true
		return nil
	})
	if err != nil {
		return fleet.OwnerBinding{}, false, live.ErrUnavailable
	}
	return out, found, nil
}
