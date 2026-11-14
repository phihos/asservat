package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RemoteCapacity stores and reads the latest capacity observation of each
// workload cluster joined with mode: cluster (ADR-330). The federation
// stores a delivery under its connector's authenticated cluster; the
// hub-worker's capacity reconciler reads it. A row is an observation only.
type RemoteCapacity struct {
	pool *pgxpool.Pool
	root string
}

func NewRemoteCapacity(pool *pgxpool.Pool, root string) (*RemoteCapacity, error) {
	if pool == nil || !authorization.UUID(root) {
		return nil, cfg.ErrInvalid
	}
	return &RemoteCapacity{pool: pool, root: root}, nil
}

// StoreRemoteCapacity records c unless a newer observation of its cluster
// is already stored.
func (s *RemoteCapacity) StoreRemoteCapacity(ctx context.Context, c app.RemoteCapacity) error {
	if s == nil || ctx == nil || !c.Valid() {
		return cfg.ErrInvalid
	}
	body, err := json.Marshal(c.Namespaces)
	if err != nil {
		return cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	_, err = s.pool.Exec(call, `INSERT INTO public.remote_capacity_delivery(root_id,cluster_id,observed_at,namespaces) VALUES($1,$2,$3,$4)
ON CONFLICT(root_id,cluster_id) DO UPDATE SET observed_at=excluded.observed_at,namespaces=excluded.namespaces
WHERE remote_capacity_delivery.observed_at<excluded.observed_at`, id(s.root), id(c.ClusterID), ts(c.ObservedAt), body)
	if err != nil {
		return cfg.ErrUnavailable
	}
	return nil
}

// RemoteCapacity returns cluster's latest stored observation.
func (s *RemoteCapacity) RemoteCapacity(ctx context.Context, cluster string) (app.RemoteCapacity, error) {
	out := app.RemoteCapacity{ClusterID: cluster}
	if s == nil || ctx == nil || !authorization.UUID(cluster) {
		return out, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	var body []byte
	err := s.pool.QueryRow(call, `SELECT observed_at,namespaces FROM public.remote_capacity_delivery WHERE root_id=$1 AND cluster_id=$2`, id(s.root), id(cluster)).Scan(&out.ObservedAt, &body)
	if errors.Is(err, pgx.ErrNoRows) || err != nil || json.Unmarshal(body, &out.Namespaces) != nil || !out.Valid() {
		return app.RemoteCapacity{}, cfg.ErrUnavailable
	}
	return out, nil
}
