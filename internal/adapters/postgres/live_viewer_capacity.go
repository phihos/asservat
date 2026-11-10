package postgres

import (
	"context"
	"fmt"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	liveapp "asservat.local/asservat/internal/application/live"
	"asservat.local/asservat/internal/domain/authorization"
	v "asservat.local/asservat/internal/domain/live"
	"github.com/jackc/pgx/v5/pgxpool"
)

type LiveViewerCapacity struct {
	ledger       *Ledger
	installation string
}

var _ liveapp.CapacityViewers = (*LiveViewerCapacity)(nil)

func NewLiveViewerCapacity(ctx context.Context, pool *pgxpool.Pool, installation string) (*LiveViewerCapacity, error) {
	if !authorization.UUID(installation) {
		return nil, fmt.Errorf("%w: live_viewer_capacity:39", v.ErrInvalid)
	}
	ledger, err := New(ctx, pool)
	if err != nil {
		return nil, fmt.Errorf("%w: live_viewer_capacity:43", v.ErrUnavailable)
	}
	return &LiveViewerCapacity{ledger: ledger, installation: installation}, nil
}

func (s *LiveViewerCapacity) ReadLiveViewers(ctx context.Context, installation, cluster string) (int, time.Time, error) {
	if s == nil || s.ledger == nil || installation != s.installation || !authorization.UUID(cluster) {
		return 0, time.Time{}, fmt.Errorf("%w: live_viewer_capacity:52", v.ErrInvalid)
	}
	clusterKey, _ := liveClusterKey(cluster)
	count := int64(-1)
	fresh := time.Time{}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		count, err = q.ReadLiveViewers(ctx, custodydb.ReadLiveViewersParams{InstallationID: id(installation), ClusterKey: clusterKey[:]})
		if err != nil {
			return err
		}
		fresh = now.Time.Add(5 * time.Second)
		return ctx.Err()
	})
	if err != nil || count < 0 || count > 65536 || fresh.IsZero() {
		return 0, time.Time{}, fmt.Errorf("%w: live_viewer_capacity:72", v.ErrUnavailable)
	}
	return int(count), fresh, nil
}
