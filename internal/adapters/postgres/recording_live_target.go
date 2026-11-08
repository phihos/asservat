package postgres

import (
	"context"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
)

// LiveSourceTarget returns only a locator in this protected root. Neither a
// current policy join nor a source UUID grants observation rights. C3 must
// check current ordinary entitlement before reading the full source/audience.
func (s *ContextPreviews) LiveSourceTarget(ctx context.Context, sourceID string) (authorization.Target, error) {
	var out authorization.Target
	if s == nil || s.ledger == nil || ctx == nil || !authorization.UUID(sourceID) {
		return out, value.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, err := q.ReadLiveSourceTarget(ctx, custodydb.ReadLiveSourceTargetParams{RootID: id(s.root), ID: id(sourceID)})
		if err != nil {
			return err
		}
		out = authorization.Target{ClusterID: uid(row.ClusterID), NamespaceUID: row.NamespaceUid, WorkloadUID: row.WorkloadUid, PodUID: row.PodUid}
		if !out.Valid() {
			return value.ErrUnavailable
		}
		return ctx.Err()
	})
	if err != nil {
		return authorization.Target{}, captureError(err)
	}
	return out, nil
}
