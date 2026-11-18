package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
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
	unavailable bool
	bindings    []cfg.Binding
	digest      []byte
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

// BeginRemoteBindings establishes a durable predecessor before the connector
// reads Kubernetes. A new registration grants nothing until its first LIST.
func (s *RemoteAccessBindings) BeginRemoteBindings(ctx context.Context, cluster string) (string, error) {
	_, revision, err := s.RemoteBindingsDigest(ctx, cluster)
	if err != nil || revision != "" {
		return revision, err
	}
	marker := contracts.AccessBindingDelivery{Unavailable: true}
	sum, _ := hex.DecodeString(marker.Digest())
	err = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		token, err := q.InsertRemoteAccessBindings(ctx, custodydb.InsertRemoteAccessBindingsParams{RootID: id(s.root), ClusterID: id(cluster), Digest: sum, Bindings: []byte("[]"), Unavailable: true})
		if errors.Is(err, pgx.ErrNoRows) {
			return cfg.ErrChanged
		}
		revision = uid(token)
		return err
	})
	if err == nil {
		return revision, nil
	}
	if !errors.Is(err, cfg.ErrChanged) {
		return "", permissionError(err)
	}
	// Another transaction initialized the registration. A concurrent
	// withdrawal can also remove it again before this read.
	_, revision, err = s.RemoteBindingsDigest(ctx, cluster)
	if err == nil && revision == "" {
		return "", cfg.ErrChanged
	}
	return revision, err
}

// StoreRemoteBindings confirms the exact predecessor the connector compared.
// A concurrent commit makes this exchange retry from a fresh workload LIST.
func (s *RemoteAccessBindings) StoreRemoteBindings(ctx context.Context, cluster string, previous, digest string, bindings []cfg.Binding, unavailable bool) (string, error) {
	if !authorization.UUID(previous) {
		return "", cfg.ErrChanged
	}
	sum, err := hex.DecodeString(digest)
	if s == nil || ctx == nil || !cfg.ValidClusterBindings(cluster, bindings) || err != nil || len(sum) != sha256.Size {
		return "", cfg.ErrInvalid
	}
	body, err := json.Marshal(bindings)
	// The normalized SQL representation is independently bounded at 32 MiB
	// by remote_access_binding_delivery_bindings_check.
	if len(body) > 32<<20 {
		unavailable = true
	}
	if unavailable {
		body = []byte("[]")
	}
	if err != nil {
		return "", cfg.ErrInvalid
	}
	var token pgtype.UUID
	err = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		var err error
		token, err = q.ReplaceRemoteAccessBindings(ctx, custodydb.ReplaceRemoteAccessBindingsParams{RootID: id(s.root), ClusterID: id(cluster), Previous: id(previous), Digest: sum, Bindings: body, Unavailable: unavailable})
		if errors.Is(err, pgx.ErrNoRows) {
			return cfg.ErrChanged
		}
		return err
	})
	if err != nil {
		return "", permissionError(err)
	}
	return uid(token), nil
}

// RemoteBindingsDigest returns the digest and revision atomically. An absent
// row has an empty digest and revision.
func (s *RemoteAccessBindings) RemoteBindingsDigest(ctx context.Context, cluster string) (string, string, error) {
	if s == nil || ctx == nil || !authorization.UUID(cluster) {
		return "", "", cfg.ErrInvalid
	}
	var observation custodydb.ReadRemoteAccessBindingDigestRow
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) (err error) {
		observation, err = q.ReadRemoteAccessBindingDigest(ctx, custodydb.ReadRemoteAccessBindingDigestParams{RootID: id(s.root), ClusterID: id(cluster)})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	if err != nil || !observation.Revision.Valid {
		return "", "", permissionError(err)
	}
	return hex.EncodeToString(observation.Digest), uid(observation.Revision), nil
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
	// The single SELECT reads a consistent snapshot. Pool acquisition and SQL
	// execution have separate I/O bounds, both inside the caller's lease.
	acquire, cancel := context.WithTimeout(ctx, 5*time.Second)
	conn, err := s.ledger.pool.Acquire(acquire)
	cancel()
	if err != nil {
		return nil, permissionError(err)
	}
	query, cancel := context.WithTimeout(ctx, 5*time.Second)
	rows, err := custodydb.New(conn).ListRemoteAccessBindings(query, params)
	cancel()
	conn.Release()
	if err != nil {
		return nil, permissionError(err)
	}
	out := make([]cfg.RemoteBindings, 0, len(rows))
	next := make(map[string]cachedRemoteBindings, len(rows))
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, permissionError(err)
		}
		cluster := uid(row.ClusterID)
		cached := s.cache[cluster]
		if row.Bindings != nil {
			var bindings []cfg.Binding
			if err := json.Unmarshal(row.Bindings, &bindings); err != nil {
				return nil, cfg.ErrInvalid
			}
			cached = cachedRemoteBindings{bindings: bindings, digest: row.Digest, unavailable: row.Unavailable}
		}
		next[cluster] = cached
		out = append(out, cfg.RemoteBindings{ClusterID: cluster, ObservedAt: row.ObservedAt.Time, Digest: [32]byte(row.Digest), Bindings: cached.bindings, Unavailable: cached.unavailable})
	}
	if err := ctx.Err(); err != nil {
		return nil, permissionError(err)
	}
	s.cache = next
	return out, nil
}
