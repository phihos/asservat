package postgres

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	capacity "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CapacityClusterQualifications are migration 00065's write-once regional
// cluster qualifications for one permission root (ADR-197). The hub-api
// writes one per guarded catalog entry; the hub-worker reads them as its
// regional namespace pins. Neither call confers observation authority.
type CapacityClusterQualifications struct {
	ledger *Ledger
	root   string
}

func NewCapacityClusterQualifications(ctx context.Context, pool *pgxpool.Pool, root string) (*CapacityClusterQualifications, error) {
	if !authorization.UUID(root) {
		return nil, value.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	return &CapacityClusterQualifications{ledger: l, root: root}, nil
}

// QualifyCapacityCluster inserts the cluster's row or replays it exactly; a
// different existing row is refused.
func (s *CapacityClusterQualifications) QualifyCapacityCluster(ctx context.Context, cluster, peer, epoch string, digest artifact.Digest, keys []string) error {
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(cluster) || !authorization.UUID(peer) || !authorization.UUID(epoch) || digest == (artifact.Digest{}) || !capacityKeys(keys) {
		return value.ErrInvalid
	}
	raw, err := json.Marshal(keys)
	if err != nil {
		return value.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	_, err = custodydb.New(s.ledger.pool).QualifyCapacityCluster(call, custodydb.QualifyCapacityClusterParams{RootID: id(s.root), ClusterID: id(cluster), PeerID: id(peer), IssuerEpoch: id(epoch), GuardDigest: digest[:], GuardKeys: raw})
	if err != nil {
		return value.ErrUnavailable
	}
	return nil
}

// ReadCapacityClusterQualifications returns the root's regional pins in
// cluster order, in the qualification's namespace pin shape.
func (s *CapacityClusterQualifications) ReadCapacityClusterQualifications(ctx context.Context) ([]capacity.CapacityNamespaceQualification, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, value.ErrUnavailable
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	raw, err := custodydb.New(s.ledger.pool).ReadCapacityClusterQualifications(call, id(s.root))
	if err != nil {
		// A timed-out query separates pool or server waits from a refusal
		// (ADR-197 CI continuation run 17a never logged its failed reads).
		if call.Err() != nil {
			return nil, registryStep("query-timeout", err)
		}
		return nil, registryStep("query", err)
	}
	if len(raw) > 1<<20 {
		return nil, value.ErrUnavailable
	}
	var rows []struct {
		ClusterID, PeerID, IssuerEpoch string
		Digest                         artifact.Digest
		Keys                           []string
	}
	if strictJSON(string(raw), &rows) != nil || len(rows) > 15 {
		return nil, value.ErrUnavailable
	}
	out := make([]capacity.CapacityNamespaceQualification, 0, len(rows))
	for i, r := range rows {
		if !authorization.UUID(r.ClusterID) || !authorization.UUID(r.PeerID) || !authorization.UUID(r.IssuerEpoch) || r.Digest == (artifact.Digest{}) || !capacityKeys(r.Keys) || i > 0 && rows[i-1].ClusterID >= r.ClusterID {
			return nil, value.ErrUnavailable
		}
		out = append(out, capacity.CapacityNamespaceQualification{ClusterID: r.ClusterID, Digest: r.Digest, Keys: r.Keys})
	}
	return out, nil
}

// capacityKeys are one to 256 strictly ascending selector keys.
func capacityKeys(keys []string) bool {
	if len(keys) < 1 || len(keys) > 256 || !slices.IsSorted(keys) {
		return false
	}
	for i, k := range keys {
		if !identity.Text(k, 253) || i > 0 && keys[i-1] == k {
			return false
		}
	}
	return true
}
