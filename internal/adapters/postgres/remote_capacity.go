package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RemoteCapacity stores and reads the latest capacity observation of each
// workload cluster joined with mode: cluster (ADR-331). The federation
// stores a delivery under its connector's authenticated cluster; the
// hub-worker keeps every cluster's row in memory, reloaded when the table's
// trigger notifies a change (Watch). A row is an observation only.
type RemoteCapacity struct {
	pool *pgxpool.Pool
	root string
	mu   sync.Mutex
	// rows is the in-memory copy (Watch); nil until the first load.
	rows map[string]app.RemoteCapacity
}

func NewRemoteCapacity(pool *pgxpool.Pool, root string) (*RemoteCapacity, error) {
	if pool == nil || !authorization.UUID(root) {
		return nil, cfg.ErrInvalid
	}
	return &RemoteCapacity{pool: pool, root: root}, nil
}

// StoreRemoteCapacity records c with its delivery digest (hex,
// contracts.CapacityDelivery.Digest) unless a newer observation of its
// cluster is already stored.
func (s *RemoteCapacity) StoreRemoteCapacity(ctx context.Context, c app.RemoteCapacity, digest string) error {
	sum, err := hex.DecodeString(digest)
	if s == nil || ctx == nil || !c.Valid() || err != nil || len(sum) != sha256.Size {
		return cfg.ErrInvalid
	}
	body, err := json.Marshal(c.Namespaces)
	if err != nil {
		return cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	_, err = s.pool.Exec(call, `INSERT INTO public.remote_capacity_delivery(root_id,cluster_id,observed_at,digest,namespaces) VALUES($1,$2,$3,$4,$5)
ON CONFLICT(root_id,cluster_id) DO UPDATE SET observed_at=excluded.observed_at,digest=excluded.digest,namespaces=excluded.namespaces
WHERE remote_capacity_delivery.observed_at<excluded.observed_at
 OR (remote_capacity_delivery.observed_at=excluded.observed_at AND remote_capacity_delivery.digest<>excluded.digest)`, id(s.root), id(c.ClusterID), ts(c.ObservedAt), sum, body)
	if err != nil {
		return cfg.ErrUnavailable
	}
	return nil
}

// RemoteCapacityDigest is cluster's stored delivery digest (hex), "" when
// none is stored.
func (s *RemoteCapacity) RemoteCapacityDigest(ctx context.Context, cluster string) (string, error) {
	if s == nil || ctx == nil || !authorization.UUID(cluster) {
		return "", cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	var sum []byte
	err := s.pool.QueryRow(call, `SELECT digest FROM public.remote_capacity_delivery WHERE root_id=$1 AND cluster_id=$2`, id(s.root), id(cluster)).Scan(&sum)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", cfg.ErrUnavailable
	}
	return hex.EncodeToString(sum), nil
}

// Watch keeps the in-memory rows current until ctx ends: a full reload at
// each notification and whenever the notification connection is
// (re)established. report receives fixed outcome words.
func (s *RemoteCapacity) Watch(ctx context.Context, report func(string)) {
	changes := Listen(ctx, s.pool, RemoteCapacityChannel)
	for {
		select {
		case <-ctx.Done():
			return
		case <-changes:
		}
		if err := s.load(ctx); err != nil {
			report("reload unavailable")
		}
	}
}

func (s *RemoteCapacity) load(ctx context.Context) error {
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	rows, err := s.pool.Query(call, `SELECT cluster_id,observed_at,namespaces FROM public.remote_capacity_delivery WHERE root_id=$1 ORDER BY cluster_id LIMIT 64`, id(s.root))
	if err != nil {
		return cfg.ErrUnavailable
	}
	defer rows.Close()
	next := map[string]app.RemoteCapacity{}
	for rows.Next() {
		var c app.RemoteCapacity
		var cluster pgtype.UUID
		var body []byte
		if rows.Scan(&cluster, &c.ObservedAt, &body) != nil {
			return cfg.ErrUnavailable
		}
		c.ClusterID = uid(cluster)
		if json.Unmarshal(body, &c.Namespaces) != nil || !c.Valid() {
			continue // an unreadable row backs nothing
		}
		next[c.ClusterID] = c
	}
	if rows.Err() != nil {
		return cfg.ErrUnavailable
	}
	s.mu.Lock()
	s.rows = next
	s.mu.Unlock()
	return nil
}

// RemoteCapacity returns cluster's latest delivered observation from memory.
func (s *RemoteCapacity) RemoteCapacity(_ context.Context, cluster string) (app.RemoteCapacity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.rows[cluster]
	if !ok {
		return app.RemoteCapacity{}, cfg.ErrUnavailable
	}
	return c, nil
}
