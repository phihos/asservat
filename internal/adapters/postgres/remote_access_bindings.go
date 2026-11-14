package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"sync"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
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
	cache  map[string]cfg.RemoteBindings // by cluster, for the stored digest
	digest map[string][]byte
}

func NewRemoteAccessBindings(ctx context.Context, pool *pgxpool.Pool, root string) (*RemoteAccessBindings, error) {
	if !authorization.UUID(root) {
		return nil, cfg.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	return &RemoteAccessBindings{ledger: l, root: root, cache: map[string]cfg.RemoteBindings{}, digest: map[string][]byte{}}, nil
}

// StoreRemoteBindings records d unless a newer delivery of its cluster is
// already stored.
func (s *RemoteAccessBindings) StoreRemoteBindings(ctx context.Context, d cfg.RemoteBindings) error {
	if s == nil || ctx == nil || !d.Valid() {
		return cfg.ErrInvalid
	}
	body, err := json.Marshal(d.Bindings)
	if err != nil {
		return cfg.ErrInvalid
	}
	sum := sha256.Sum256(body)
	return permissionError(s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		_, err := q.StoreRemoteAccessBindings(ctx, custodydb.StoreRemoteAccessBindingsParams{RootID: id(s.root), ClusterID: id(d.ClusterID), ObservedAt: ts(d.ObservedAt), Digest: sum[:], Bindings: body})
		return err
	}))
}

// RemoteBindings returns every cluster's latest delivery. Bindings are read
// and decoded only when a cluster's stored digest changed.
func (s *RemoteAccessBindings) RemoteBindings(ctx context.Context) ([]cfg.RemoteBindings, error) {
	if s == nil || ctx == nil {
		return nil, cfg.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []cfg.RemoteBindings
	var next map[string]cfg.RemoteBindings
	var digests map[string][]byte
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		out, next, digests = nil, map[string]cfg.RemoteBindings{}, map[string][]byte{}
		rows, err := q.ListRemoteAccessBindingDigests(ctx, id(s.root))
		if err != nil {
			return err
		}
		for _, row := range rows {
			cluster := uid(row.ClusterID)
			d, known := s.cache[cluster]
			d.ObservedAt = row.ObservedAt.Time
			if !known || !bytes.Equal(s.digest[cluster], row.Digest) {
				full, err := q.ReadRemoteAccessBindings(ctx, custodydb.ReadRemoteAccessBindingsParams{RootID: id(s.root), ClusterID: row.ClusterID})
				if err != nil {
					return err
				}
				d = cfg.RemoteBindings{ClusterID: cluster, ObservedAt: full.ObservedAt.Time}
				if sum := sha256.Sum256(full.Bindings); !bytes.Equal(sum[:], full.Digest) || json.Unmarshal(full.Bindings, &d.Bindings) != nil {
					continue // an unreadable row grants and denies nothing
				}
				row.Digest = full.Digest
			}
			next[cluster], digests[cluster] = d, row.Digest
			out = append(out, d)
		}
		return nil
	})
	if err != nil {
		return nil, permissionError(err)
	}
	s.cache, s.digest = next, digests
	return out, nil
}
