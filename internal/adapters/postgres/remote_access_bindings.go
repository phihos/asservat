package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RemoteAccessBindings stores and reads the latest AccessBinding delivery of
// each workload cluster joined with mode: cluster (ADR-329). The federation
// stores a delivery under its connector's authenticated cluster; the
// permission reconciler reads all of them. A row is an observation only.
type RemoteAccessBindings struct {
	ledger *Ledger
	root   string
	mu     sync.Mutex
	cache  map[string]cachedRemoteBindings
}

type cachedRemoteBindings struct {
	bindings []cfg.Binding
	digest   []byte
}

func NewRemoteAccessBindings(ctx context.Context, pool *pgxpool.Pool, root string) (*RemoteAccessBindings, error) {
	if !authorization.UUID(root) {
		return nil, cfg.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	return &RemoteAccessBindings{ledger: l, root: root}, nil
}

// StoreRemoteBindings records d with its delivery digest (hex,
// contracts.AccessBindingDelivery.Digest) unless a newer delivery of its
// cluster is already stored. The table's trigger notifies the hub-worker.
func (s *RemoteAccessBindings) StoreRemoteBindings(ctx context.Context, d cfg.RemoteBindings, digest string) error {
	sum, err := hex.DecodeString(digest)
	if s == nil || ctx == nil || !d.Valid() || err != nil || len(sum) != sha256.Size {
		return cfg.ErrInvalid
	}
	body, err := json.Marshal(d.Bindings)
	if err != nil {
		return cfg.ErrInvalid
	}
	return permissionError(s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		_, err := q.StoreRemoteAccessBindings(ctx, custodydb.StoreRemoteAccessBindingsParams{RootID: id(s.root), ClusterID: id(d.ClusterID), ObservedAt: ts(d.ObservedAt), Digest: sum, Bindings: body})
		return err
	}))
}

// RemoteBindingsDigest is cluster's stored delivery digest (hex), "" when
// none is stored.
func (s *RemoteAccessBindings) RemoteBindingsDigest(ctx context.Context, cluster string) (string, error) {
	if s == nil || ctx == nil || !authorization.UUID(cluster) {
		return "", cfg.ErrInvalid
	}
	var out string
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		d, err := q.ReadRemoteAccessBindingDigest(ctx, custodydb.ReadRemoteAccessBindingDigestParams{RootID: id(s.root), ClusterID: id(cluster)})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		out = hex.EncodeToString(d)
		return err
	})
	return out, permissionError(err)
}

// RemoteBindings returns every cluster's latest delivery. Bindings are read
// and decoded only when a cluster's stored digest changed.
func (s *RemoteAccessBindings) RemoteBindings(ctx context.Context) ([]cfg.RemoteBindings, error) {
	if s == nil || ctx == nil {
		return nil, cfg.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	params := custodydb.ListRemoteAccessBindingsParams{RootID: id(s.root)}
	for cluster, cached := range s.cache {
		params.ClusterIds = append(params.ClusterIds, id(cluster))
		params.Digests = append(params.Digests, cached.digest)
	}
	var out []cfg.RemoteBindings
	var next map[string]cachedRemoteBindings
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		rows, err := q.ListRemoteAccessBindings(ctx, params)
		if err != nil {
			return err
		}
		out = make([]cfg.RemoteBindings, 0, len(rows))
		next = make(map[string]cachedRemoteBindings, len(rows))
		for _, row := range rows {
			cluster := uid(row.ClusterID)
			cached := s.cache[cluster]
			if row.Bindings != nil {
				var bindings []cfg.Binding
				if err := json.Unmarshal(row.Bindings, &bindings); err != nil {
					return cfg.ErrInvalid
				}
				cached = cachedRemoteBindings{bindings: bindings, digest: row.Digest}
			}
			next[cluster] = cached
			out = append(out, cfg.RemoteBindings{ClusterID: cluster, ObservedAt: row.ObservedAt.Time, Digest: [32]byte(row.Digest), Bindings: cached.bindings})
		}
		return nil
	})
	if err != nil {
		return nil, permissionError(err)
	}
	s.cache = next
	return out, nil
}
